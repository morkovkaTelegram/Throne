#include "include/configs/sub/GroupUpdater.hpp"

#include "include/configs/generate.h"
#include "include/configs/sub/ImportReport.hpp"
#include "include/configs/sub/SubscriptionParser.hpp"
#include "include/configs/sub/SubscriptionReconcile.hpp"
#include "include/configs/sub/SubscriptionScan.hpp"
#include "include/configs/sub/ServerFilter.hpp"
#include "include/database/GroupsRepo.h"
#include "include/database/ProfilesRepo.h"
#include "include/engine/EngineEvents.h"
#include "include/global/HTTPRequestHelper.hpp"
#include "include/global/Notice.hpp"
#include "include/global/Utils.hpp"

#include <QCoreApplication>
#include <QCryptographicHash>
#include <QDateTime>
#include <QJsonDocument>
#include <QMutexLocker>
#include <QRegularExpression>
#include <QThreadPool>
#include <QUrl>

#include <algorithm>
#include <atomic>

namespace Subscription {
    namespace {
        constexpr int kInsertChunk = 500;
        constexpr qint64 kMaxSubscriptionBytes = 64LL * 1024 * 1024;
        constexpr qsizetype kMaxHeaderValue = 1000;
        constexpr int kValidityCheckThreads = 10;

        QByteArray digest(const QByteArray &data) {
            return QCryptographicHash::hash(data, QCryptographicHash::Sha256);
        }

        QByteArray contentKeyOf(const Configs::Profile &ent) {
            return digest(QJsonDocument(ent.outbound->ExportToJson()).toJson(QJsonDocument::Compact));
        }

        QByteArray identityKeyOf(const Configs::Profile &ent) {
            return digest(ent.type.toUtf8() + '|' + QJsonDocument(ent.outbound->ExportIdentity()).toJson(QJsonDocument::Compact));
        }

        bool usableHeaderValue(const QString &value) {
            return !value.isEmpty() && value.size() < kMaxHeaderValue && !value.contains('\n') && !value.contains('\r');
        }

        void applyCustomHwidParams(DeviceDetails &device, const QString &params) {
            for (const auto &pair : params.split(',')) {
                const auto trimmed = pair.trimmed();
                const auto eqPos = trimmed.indexOf('=');
                if (eqPos <= 0) continue;
                const auto key = trimmed.left(eqPos).trimmed().toLower();
                const auto value = trimmed.mid(eqPos + 1).trimmed();
                if (!usableHeaderValue(value)) continue;
                if (key == "hwid") device.hwid = value;
                else if (key == "os") device.os = value;
                else if (key == "osversion") device.osVersion = value;
                else if (key == "model") device.model = value;
            }
        }

        QList<QPair<QByteArray, QByteArray>> identityHeaders(const RequestIdentity &identity) {
            QList<QPair<QByteArray, QByteArray>> headers;
            if (!identity.sendHwid) return headers;
            const auto add = [&headers](const char *name, const QString &value) {
                if (usableHeaderValue(value)) headers.append({name, value.toUtf8()});
            };
            add("x-hwid", identity.device.hwid);
            add("x-device-os", identity.device.os);
            add("x-ver-os", identity.device.osVersion);
            add("x-device-model", identity.device.model);
            return headers;
        }

        QSsl::SslProtocol tlsProtocolOf(Configs::subTlsVersion version) {
            switch (version) {
                case Configs::subTlsVersion::tls12: return QSsl::TlsV1_2;
                case Configs::subTlsVersion::tls13: return QSsl::TlsV1_3;
                default: return QSsl::SecureProtocols;
            }
        }

        bool looksLikeWebPage(const QByteArray &body) {
            const auto text = scan::trim(scan::view(body));
            return scan::startsWithNoCase(text, "<!doctype html") || scan::startsWithNoCase(text, "<html");
        }

        template <typename Visit>
        void forEachProfile(const QList<int> &ids, Visit &&visit) {
            for (qsizetype off = 0; off < ids.size(); off += Configs::BATCH_LIMIT_READ) {
                for (const auto &ent : Configs::dataManager->profilesRepo->GetProfileBatch(ids.mid(off, Configs::BATCH_LIMIT_READ))) {
                    if (ent != nullptr) visit(ent);
                }
            }
        }

        // Auto selectors are local state, not servers the remote sent.
        QList<int> withoutSelectors(const QList<int> &ids) {
            const auto selectorIds = Configs::dataManager->profilesRepo->GetProfileIdsByType("autoselector");
            const QSet<int> selectors(selectorIds.begin(), selectorIds.end());
            QList<int> result;
            for (int id : ids) {
                if (!selectors.contains(id)) result << id;
            }
            return result;
        }

        // BatchDeleteProfiles silently drops the running profile from the list it was handed (#1753).
        struct DeleteOutcome {
            bool ok = false;
            QList<int> deleted;
            QList<int> kept;
        };

        DeleteOutcome deleteProfiles(QList<int> ids) {
            DeleteOutcome outcome;
            const QSet<int> requested(ids.begin(), ids.end());
            outcome.ok = Configs::dataManager->profilesRepo->BatchDeleteProfiles(
                ids, Configs::dataManager->settingsRepo->allow_stopping_active_profile, false);
            const QSet<int> deleted(ids.begin(), ids.end());
            outcome.deleted = std::move(ids);
            for (int id : requested) {
                if (!deleted.contains(id)) outcome.kept << id;
            }
            return outcome;
        }

        // Inserts in chunks; only per-profile digests survive a flush.
        class ImportSink {
        public:
            ImportSink(int gid, ContentIndex *index) : gid(gid), index(index) {}

            void add(std::shared_ptr<Configs::Profile> ent) {
                NewEntry entry;
                entry.display = ent->outbound->DisplayTypeAndName();
                if (index != nullptr) {
                    entry.keys.content = contentKeyOf(*ent);
                    index->noteArrival(entry.keys.content);
                    entry.contentKnown = index->knows(entry.keys.content);
                    if (const auto oldId = index->claim(entry.keys.content)) {
                        entry.id = *oldId;
                        entry.reused = true;
                        entries.append(std::move(entry));
                        return;
                    }
                    if (!entry.contentKnown) entry.keys.identity = identityKeyOf(*ent);
                }
                entryIndex.append(entries.size());
                entries.append(std::move(entry));
                chunk.append(std::move(ent));
                if (chunk.size() >= kInsertChunk) flush();
            }

            void flush() {
                if (chunk.isEmpty()) return;
                if (Configs::dataManager->profilesRepo->AddProfileBatch(chunk, gid)) {
                    for (qsizetype i = 0; i < chunk.size(); ++i) {
                        entries[entryIndex[i]].id = chunk[i]->id;
                        added << chunk[i]->id;
                    }
                    destination = chunk.first()->gid;
                }
                chunk.clear();
                entryIndex.clear();
            }

            // Sorted here rather than queued, so the SubscriptionFinished redraw already shows the order.
            void finish() {
                flush();
                const auto group = Configs::dataManager->groupsRepo->GetGroup(destination);
                if (group != nullptr && group->Reposition(added)) Configs::dataManager->groupsRepo->Save(group);
            }

            // Rows that really reached the database: added, or reused from the group.
            [[nodiscard]] int stored() const {
                return static_cast<int>(std::count_if(entries.cbegin(), entries.cend(), [](const NewEntry &e) { return e.id >= 0; }));
            }

            [[nodiscard]] QList<int> storedIds() const {
                QList<int> ids;
                for (const auto &entry : entries) {
                    if (entry.id >= 0) ids << entry.id;
                }
                return ids;
            }

            QList<NewEntry> entries;

        private:
            int gid;
            int destination = -1;
            QList<int> added;
            ContentIndex *index;
            QList<std::shared_ptr<Configs::Profile>> chunk;
            QList<qsizetype> entryIndex;
        };

        ParseSink sinkFor(ImportSink &sink, ImportReport &report, const QList<ServerFilter::Rule> &filterRules = {}) {
            ParseSink parseSink;
            parseSink.profile = [&sink, filterRules](std::shared_ptr<Configs::Profile> ent) {
                if (ServerFilter::matches(ent, filterRules)) return;
                sink.add(std::move(ent));
            };
            parseSink.report = [&report](const ParseReport &item) { report.add(item); };
            return parseSink;
        }

        // A dry run, as the real parse inserts as it goes. Its diagnostics only matter when it finds nothing: otherwise the real parse repeats them.
        bool yieldsProfile(const QByteArray &body, ImportReport &diagnostics) {
            bool found = false;
            ParseSink probe;
            probe.profile = [&found](const std::shared_ptr<Configs::Profile> &) { found = true; };
            probe.report = [&diagnostics](const ParseReport &item) { diagnostics.add(item); };
            ParseDocument(body, probe);
            return found;
        }

        void logImportReport(const ImportReport &report) {
            QString text = report.summary();
            if (const auto details = report.details(); !details.isEmpty()) text += '\n' + details;
            MW_show_log(text);
        }

        // Qt's HTTP error text embeds the request (or redirect) URL, and with it the subscription token.
        QString withoutUrls(const QString &text, const QString &url) {
            const auto hostOf = [](const QUrl &u) { return u.host().isEmpty() ? QString(QChar(0x2026)) : u.host(); };
            const QUrl parsed(url);
            QString redacted = text;
            for (const auto &form : {url, parsed.toString(), parsed.toString(QUrl::FullyEncoded), parsed.toDisplayString()}) {
                if (!form.isEmpty()) redacted.replace(form, hostOf(parsed));
            }
            static const QRegularExpression urlRe(R"([A-Za-z][A-Za-z0-9+.\-]*://[^\s"'<>]+)");
            QString result;
            qsizetype last = 0;
            for (auto it = urlRe.globalMatch(redacted); it.hasNext();) {
                const auto match = it.next();
                result += QStringView(redacted).mid(last, match.capturedStart() - last);
                result += hostOf(QUrl(match.captured()));
                last = match.capturedEnd();
            }
            result += QStringView(redacted).mid(last);
            return result;
        }

        QString fetchFailure(const QString &error) {
            return QCoreApplication::translate("Validation", "Could not download the subscription: %1").arg(error);
        }

        QString groupUpdaterWebPageReason(const QByteArray &body) {
            return looksLikeWebPage(body)
                ? QCoreApplication::translate("Validation", "The server returned a web page instead of a subscription.")
                : QString();
        }

        // Outcome errors reach the API, so they stay English.
        UpdateOutcome groupUpdaterFailure(int gid, UpdateOutcome::Failure failure, the rest of the file is too large for this call - WILL CONTINUE WITH PATCH APPROACH
