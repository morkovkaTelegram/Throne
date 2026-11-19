#include "include/configs/sub/SubscriptionFilter.hpp"

#include "include/configs/common/Protocols.h"
#include "include/database/entities/Profile.h"

#include <QCoreApplication>

#include <algorithm>
#include <optional>

namespace Subscription {
    namespace {
        QString countryCode(const QString &item) {
            const auto code = item.trimmed().toUpper();
            if (code.size() != 2) return {};
            for (const QChar c : code) {
                if (c < QLatin1Char('A') || c > QLatin1Char('Z')) return {};
            }
            return code == QLatin1String("UK") ? QStringLiteral("GB") : code;
        }

        QList<std::pair<QString, bool>> countryItems(const QString &text, QStringList *problems) {
            QList<std::pair<QString, bool>> items;
            for (const auto &raw : text.split(QLatin1Char(','), Qt::SkipEmptyParts)) {
                auto item = raw.trimmed();
                if (item.isEmpty()) continue;
                const bool drop = item.startsWith(QLatin1Char('!'));
                const auto code = countryCode(drop ? item.mid(1) : item);
                if (code.isEmpty()) {
                    if (problems != nullptr) *problems << item;
                    continue;
                }
                items.append({code, drop});
            }
            return items;
        }

        QString wildcardToRegex(const QString &pattern) {
            QString out;
            out.reserve(pattern.size() * 2);
            for (const QChar c : pattern) {
                if (c == QLatin1Char('*')) out += QStringLiteral(".*");
                else if (c == QLatin1Char('?')) out += QLatin1Char('.');
                else out += QRegularExpression::escape(QString(c));
            }
            return out;
        }

        std::optional<ExcludeRule> compileExcludeLine(QString line, QString *error) {
            line = line.trimmed();
            if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) return std::nullopt;

            ExcludeRule rule;
            auto takePrefix = [&](const QString &prefix, ExcludeRule::Field field) {
                if (!line.startsWith(prefix, Qt::CaseInsensitive)) return false;
                rule.field = field;
                line = line.mid(prefix.size()).trimmed();
                return true;
            };
            if (!takePrefix(QStringLiteral("name:"), ExcludeRule::Field::Name)
                && !takePrefix(QStringLiteral("type:"), ExcludeRule::Field::Type)
                && !takePrefix(QStringLiteral("addr:"), ExcludeRule::Field::Addr)
                && !takePrefix(QStringLiteral("server:"), ExcludeRule::Field::Addr)
                && !takePrefix(QStringLiteral("any:"), ExcludeRule::Field::Any)) {
                rule.field = ExcludeRule::Field::Name;
            }
            if (line.isEmpty()) {
                if (error) *error = QCoreApplication::translate("Validation", "Empty pattern after prefix");
                return std::nullopt;
            }

            if (line.startsWith(QStringLiteral("re:"), Qt::CaseInsensitive)) {
                const QString pattern = line.mid(3);
                if (pattern.isEmpty()) {
                    if (error) *error = QCoreApplication::translate("Validation", "Empty regex after re:");
                    return std::nullopt;
                }
                rule.isRegex = true;
                rule.regex = QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption);
                if (!rule.regex.isValid()) {
                    if (error) *error = rule.regex.errorString();
                    return std::nullopt;
                }
                return rule;
            }

            if (line.size() >= 2 && line.startsWith(QLatin1Char('/'))) {
                const int last = line.lastIndexOf(QLatin1Char('/'));
                if (last > 0) {
                    const QString pattern = line.mid(1, last - 1);
                    const QString flags = line.mid(last + 1);
                    QRegularExpression::PatternOptions opts = QRegularExpression::NoPatternOption;
                    if (flags.isEmpty() || flags.contains(QLatin1Char('i'))) {
                        opts |= QRegularExpression::CaseInsensitiveOption;
                    }
                    rule.isRegex = true;
                    rule.regex = QRegularExpression(pattern, opts);
                    if (!rule.regex.isValid()) {
                        if (error) *error = rule.regex.errorString();
                        return std::nullopt;
                    }
                    return rule;
                }
            }

            if (line.contains(QLatin1Char('*')) || line.contains(QLatin1Char('?'))) {
                rule.isRegex = true;
                rule.regex = QRegularExpression(QStringLiteral("^%1$").arg(wildcardToRegex(line)),
                                                QRegularExpression::CaseInsensitiveOption);
                if (!rule.regex.isValid()) {
                    if (error) *error = rule.regex.errorString();
                    return std::nullopt;
                }
                return rule;
            }

            rule.needle = line;
            return rule;
        }

        bool textMatches(const QString &text, const ExcludeRule &rule) {
            if (text.isEmpty() && rule.field != ExcludeRule::Field::Any) return false;
            if (rule.isRegex) return rule.regex.match(text).hasMatch();
            return text.contains(rule.needle, Qt::CaseInsensitive);
        }

        bool profileMatchesExclude(const Configs::Profile &ent, const ExcludeRule &rule) {
            const QString name = ent.outbound != nullptr ? ent.outbound->DisplayName() : ent.name;
            const QString type = ent.type;
            const QString addr = ent.outbound != nullptr ? ent.outbound->server : QString();
            switch (rule.field) {
                case ExcludeRule::Field::Name:
                    return textMatches(name, rule) || (ent.outbound != nullptr && textMatches(ent.outbound->name, rule));
                case ExcludeRule::Field::Type:
                    return textMatches(type, rule);
                case ExcludeRule::Field::Addr:
                    return textMatches(addr, rule);
                case ExcludeRule::Field::Any:
                    return textMatches(name, rule)
                           || (ent.outbound != nullptr && textMatches(ent.outbound->name, rule))
                           || textMatches(type, rule)
                           || textMatches(addr, rule);
            }
            return false;
        }
    }

    const QList<FilterProtocol> &FilterProtocols() {
        static const QList<FilterProtocol> protocols = [] {
            const auto rows = Configs::Protocols::All();
            QList<FilterProtocol> list;
            for (int rank = 1;; ++rank) {
                const auto row = std::ranges::find(rows, rank, &Configs::Protocols::ProtocolInfo::filterRank);
                if (row == rows.end()) return list;
                QStringList types{QString(row->Id())};
                for (const auto &p : rows) {
                    if (p.filterAs == row->id) types << QString(p.Id());
                }
                list.append({QString(row->Id()), row->filterLabel, types});
            }
        }();
        return protocols;
    }

    QString NamePatternProblem(const QString &pattern) {
        const auto trimmed = pattern.trimmed();
        if (trimmed.isEmpty()) return {};
        const QRegularExpression regex(trimmed, QRegularExpression::CaseInsensitiveOption);
        if (regex.isValid()) return {};
        const auto leading = pattern.indexOf(trimmed);
        return QCoreApplication::translate("Validation", "Not a valid regular expression: %1 (at character %2).")
            .arg(regex.errorString())
            .arg(leading + regex.patternErrorOffset() + 1);
    }

    QList<ExcludeRule> CompileExcludeRules(const QString &text, QStringList *problems) {
        QList<ExcludeRule> rules;
        int lineNo = 0;
        // Newlines or | separate patterns so a single-line field still accepts several rules.
        QString normalized = text;
        normalized.replace(QLatin1Char('|'), QLatin1Char('\n'));
        for (const auto &raw : normalized.split(QLatin1Char('\n'))) {
            ++lineNo;
            QString err;
            if (auto rule = compileExcludeLine(raw, &err)) {
                rules.append(std::move(*rule));
            } else if (!err.isEmpty() && problems != nullptr) {
                *problems << QCoreApplication::translate("Validation", "Line %1: %2").arg(lineNo).arg(err);
            }
        }
        return rules;
    }

    QString NameExcludeProblem(const QString &text) {
        QStringList problems;
        CompileExcludeRules(text, &problems);
        if (problems.isEmpty()) return {};
        return problems.join(QStringLiteral("; "));
    }

    bool CountryRules::accepts(const QString &country) const {
        if (country.isEmpty()) return true;
        const auto code = country.trimmed().toUpper();
        if (drop.contains(code)) return false;
        return keep.isEmpty() || keep.contains(code);
    }

    CountryRules ParseCountryRules(const QString &text, QStringList *problems) {
        CountryRules rules;
        for (const auto &[code, drop] : countryItems(text, problems)) (drop ? rules.drop : rules.keep).insert(code);
        return rules;
    }

    QString CountryRulesProblem(const QString &text) {
        QStringList problems;
        countryItems(text, &problems);
        if (problems.isEmpty()) return {};
        return QCoreApplication::translate("Validation", "Not a two-letter country code: %1. Use codes such as HK,JP to keep only those countries, or !RU to remove one.")
            .arg(problems.join(QStringLiteral(", ")));
    }

    QString NormalizeCountryRules(const QString &text) {
        QStringList keep;
        QStringList drop;
        for (const auto &[code, dropped] : countryItems(text, nullptr)) {
            auto &list = dropped ? drop : keep;
            if (!list.contains(code)) list << code;
        }
        for (const auto &code : drop) keep << QLatin1Char('!') + code;
        return keep.join(QLatin1Char(','));
    }

    ImportFilter::ImportFilter(const Configs::SubscriptionOptions &options) {
        const auto compile = [this](const QString &pattern, QRegularExpression &regex, bool &enabled, const QString &field) {
            const auto trimmed = pattern.trimmed();
            if (trimmed.isEmpty()) return;
            regex = QRegularExpression(trimmed, QRegularExpression::CaseInsensitiveOption);
            if (!regex.isValid()) {
                problems << QCoreApplication::translate("Validation", "%1 is not a valid regular expression, so it was ignored: %2").arg(field, regex.errorString());
                return;
            }
            regex.optimize();
            enabled = true;
        };
        compile(options.name_filter, nameFilter, hasNameFilter, QCoreApplication::translate("Validation", "Keep only matching"));

        QStringList excludeProblems;
        excludeRules = CompileExcludeRules(options.name_exclude, &excludeProblems);
        problems += excludeProblems;

        for (const auto &id : options.type_exclude) {
            bool known = false;
            for (const auto &protocol : FilterProtocols()) {
                if (protocol.id != id) continue;
                known = true;
                for (const auto &type : protocol.types) excludedTypes.insert(type);
            }
            if (!known) problems << QCoreApplication::translate("Validation", "Unknown protocol in Remove types, ignored: %1").arg(id);
        }

        QStringList badCodes;
        rules = ParseCountryRules(options.country_filter, &badCodes);
        if (!badCodes.isEmpty()) {
            problems << QCoreApplication::translate("Validation", "Not a two-letter country code, ignored: %1").arg(badCodes.join(QStringLiteral(", ")));
        }
    }

    ImportFilter::Verdict ImportFilter::judge(Configs::Profile &ent, const QString &country) const {
        if (excludedTypes.contains(ent.type)) return Verdict::Type;
        for (const auto &rule : excludeRules) {
            if (profileMatchesExclude(ent, rule)) return Verdict::Name;
        }
        if (hasNameFilter) {
            const auto name = ent.outbound != nullptr ? ent.outbound->DisplayName() : ent.name;
            if (!nameFilter.match(name).hasMatch()) return Verdict::Name;
        }
        if (!rules.accepts(country)) return Verdict::Country;
        return Verdict::Keep;
    }
}
