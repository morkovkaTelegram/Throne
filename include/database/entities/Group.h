#pragma once
#include <QDateTime>
#include <QJsonObject>
#include <QList>
#include <QMutex>
#include <QString>
#include <QStringList>
#include <algorithm>

#include <optional>

#include "include/database/entities/EndpointSource.h"
#include "include/database/entities/GroupSort.h"

namespace Configs
{
    struct SubUserInfo {
        bool valid = false;
        bool has_quota = false;
        qint64 upload = 0;
        qint64 download = 0;
        qint64 total = 0;
        qint64 expire = 0;

        [[nodiscard]] QString DisplayInfo() const;

        void FromHeaderContent(const QString &header);

        void FromClashYaml(const QByteArray &body);

        [[nodiscard]] QJsonObject ToJson() const;

        static SubUserInfo FromJson(const QJsonObject &json);
    };

    enum class sendHwid : int {
        keepDefault = 0,
        on,
        off
    };

    enum class subTlsVersion : int {
        automatic = 0,
        tls12,
        tls13
    };

    enum class subHttpVersion : int {
        automatic = 0,
        http11
    };

    // Empty values inherit the global subscription settings.
    struct SubscriptionOptions {
        QString user_agent;
        std::optional<subTlsVersion> tls_version;
        std::optional<subHttpVersion> http_version;
        sendHwid send_hwid = sendHwid::keepDefault;
        QString hwid;
        QString hwid_os;
        QString hwid_os_version;
        QString hwid_model;
        // Minutes; 0 follows the global interval.
        int update_interval = 0;
        std::optional<bool> respect_server_interval;
        bool keep_working = false;
        bool remove_duplicates = false;
        bool remove_insecure = false;
        bool remove_invalid = false;
        bool url_test = false;
        // Follow-ups of url_test: ignored while it is off.
        bool remove_unavailable = false;
        bool sort_by_latency = false;
        // name_filter: single regex to keep. name_exclude: multi-line flexible exclude (plain, wildcards, re:/regex/, prefixes name:/type:/addr:/any:).
        QString name_filter;
        QString name_exclude;
        // Subscription::FilterProtocols() ids.
        QStringList type_exclude;
        // "HK,JP" keeps, "!RU" drops; judged by an IP test after each update.
        QString country_filter;

        [[nodiscard]] bool SameFilters(const SubscriptionOptions &other) const;

        [[nodiscard]] QJsonObject ToJson() const;

        static SubscriptionOptions FromJson(const QJsonObject &json);
    };

    // A speed-test result such as "48.3 Mbps"; -1 for "N/A", 0 when empty.
    double bitrateToBps(const QString &str);

    // What changed under a group, so only a kept sort that reads it runs again.
    enum class SortInput {
        Membership,
        Config,
        TestResult,
        Traffic,
    };

    class Group {
    public:
        QMutex mutex;
        int id = -1;
        bool archive = false;
        bool skip_auto_update = false;
        bool auto_clear_unavailable = false;
        QString name = "";
        QString url = "";
        QString info = "";
        SubUserInfo sub_info;
        qint64 sub_last_update = 0;
        SubscriptionOptions sub_options;
        EndpointSource endpoint;
        GroupSort order;

        // Profiles currently in this group (ids).
        QList<int> order_ids;

        [[nodiscard]] QList<int> Profiles() const;

        void SetProfiles(const QList<int> &ids);

        void AddProfile(int id);

        void RemoveProfile(int id);

        [[nodiscard]] bool HasProfile(int id) const;

        [[nodiscard]] QJsonObject ToJson(const QList<int> &profiles = {}) const;

        static std::shared_ptr<Group> FromJson(const QJsonObject &object);

        // After an update, when filters change the membership may need a re-sort.
        void MarkSortDirty(SortInput input);

        [[nodiscard]] bool IsSortDirty(SortInput input) const;

        void ClearSortDirty();

    private:
        mutable QList<int> profiles;
        mutable int sort_dirty = 0;
    };
}
