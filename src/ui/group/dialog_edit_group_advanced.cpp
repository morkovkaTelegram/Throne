#include "include/ui/group/dialog_edit_group_advanced.h"

#include "include/configs/common/utils.h"
#include "include/configs/generate.h"
#include "include/configs/sub/GroupUpdater.hpp"
#include "include/configs/sub/SubscriptionFilter.hpp"
#include "include/database/DatabaseManager.h"
#include "include/database/IpListsRepo.h"
#include "include/database/SettingsRepo.h"
#include "include/ui/utils/GuiUtils.hpp"
#include "include/global/CountryHelper.hpp"
#include "include/global/Validation.hpp"
#include "include/ui/utils/ValidationForm.h"

#include <QGuiApplication>
#include <QHostAddress>
#include <QMenu>
#include <QMouseEvent>
#include <QRegularExpression>
#include <QScreen>
#include <QScrollBar>
#include <QSslSocket>
#include <QStandardItemModel>
#include <QStyle>

namespace {
    // Index 0 of an override combo is Keep Default; the enum values follow.
    template <typename E>
    int overrideIndex(const std::optional<E> &value) {
        return value ? static_cast<int>(*value) + 1 : 0;
    }

    template <typename E>
    std::optional<E> overrideAt(int index) {
        if (index <= 0) return std::nullopt;
        return static_cast<E>(index - 1);
    }

    // Empty unless the text is a bare IP address or host name: no scheme, port or path.
    QString groupEndpointHost(QString text) {
        text = text.trimmed();
        if (text.startsWith('[') && text.endsWith(']')) text = text.mid(1, text.size() - 2);
        if (IsIpAddressV6(text)) return QHostAddress(text).toString();
        // Qt reads "1.2.3" as IPv4 and "999.1.1.1" would pass as a name; both are typos, so neither is accepted.
        if (IsIpAddressV4(text)) return QHostAddress(text).toString() == text ? text : QString();
        static const QRegularExpression hostname(QStringLiteral(
            R"(^(?:(?!-)[A-Za-z0-9_-]{1,63}(?<!-)\.)*(?![0-9]+$)(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$)"));
        const auto ace = Configs::toAceHost(text);
        return ace.size() <= 253 && hostname.match(ace).hasMatch() ? ace : QString();
    }

    // GroupUpdater sends only values below 1000 characters without line breaks, and silently falls back otherwise.
    QString groupAdvancedHeaderValueError(const QString &text) {
        if (text.size() < 1000 && !text.contains(QLatin1Char('\n')) && !text.contains(QLatin1Char('\r'))) return {};
        return DialogEditGroupAdvanced::tr("Must be shorter than 1000 characters, on a single line.");
    }

    constexpr int groupAdvancedTypesTextWidth = 260;
}
