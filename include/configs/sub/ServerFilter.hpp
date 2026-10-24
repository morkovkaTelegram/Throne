#pragma once

#include "include/database/entities/Profile.h"

#include <QList>
#include <QRegularExpression>
#include <QString>

#include <memory>
#include <optional>

namespace Subscription {
namespace ServerFilter {

enum class Field { Name, Type, Addr, Any };

struct Rule {
    Field field = Field::Name;
    bool isRegex = false;
    QString needle;
    QRegularExpression regex;
};

inline QString wildcardToRegex(const QString &pattern) {
    QString out;
    out.reserve(pattern.size() * 2);
    for (const QChar c : pattern) {
        if (c == QLatin1Char('*')) out += QStringLiteral(".*");
        else if (c == QLatin1Char('?')) out += QLatin1Char('.');
        else out += QRegularExpression::escape(QString(c));
    }
    return out;
}

inline std::optional<Rule> compileLine(QString line) {
    line = line.trimmed();
    if (line.isEmpty() || line.startsWith(QLatin1Char('#'))) return std::nullopt;

    Rule rule;
    auto takePrefix = [&](const QString &prefix, Field field) {
        if (!line.startsWith(prefix, Qt::CaseInsensitive)) return false;
        rule.field = field;
        line = line.mid(prefix.size()).trimmed();
        return true;
    };
    if (!takePrefix(QStringLiteral("name:"), Field::Name)
        && !takePrefix(QStringLiteral("type:"), Field::Type)
        && !takePrefix(QStringLiteral("addr:"), Field::Addr)
        && !takePrefix(QStringLiteral("server:"), Field::Addr)
        && !takePrefix(QStringLiteral("any:"), Field::Any)) {
        rule.field = Field::Name;
    }
    if (line.isEmpty()) return std::nullopt;

    if (line.startsWith(QStringLiteral("re:"), Qt::CaseInsensitive)) {
        const QString pattern = line.mid(3);
        if (pattern.isEmpty()) return std::nullopt;
        rule.isRegex = true;
        rule.regex = QRegularExpression(pattern, QRegularExpression::CaseInsensitiveOption);
        if (!rule.regex.isValid()) return std::nullopt;
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
            if (!rule.regex.isValid()) return std::nullopt;
            return rule;
        }
    }

    if (line.contains(QLatin1Char('*')) || line.contains(QLatin1Char('?'))) {
        rule.isRegex = true;
        rule.regex = QRegularExpression(QStringLiteral("^%1$").arg(wildcardToRegex(line)),
                                        QRegularExpression::CaseInsensitiveOption);
        if (!rule.regex.isValid()) return std::nullopt;
        return rule;
    }

    rule.needle = line;
    return rule;
}

inline QList<Rule> compile(const QString &filter) {
    QList<Rule> rules;
    for (const auto &line : filter.split(QLatin1Char('\n'))) {
        if (auto rule = compileLine(line)) rules.append(std::move(*rule));
    }
    return rules;
}

inline bool textMatches(const QString &text, const Rule &rule) {
    if (text.isEmpty() && rule.field != Field::Any) return false;
    if (rule.isRegex) return rule.regex.match(text).hasMatch();
    return text.contains(rule.needle, Qt::CaseInsensitive);
}

inline bool matches(const std::shared_ptr<Configs::Profile> &ent, const QList<Rule> &rules) {
    if (rules.isEmpty() || ent == nullptr || ent->outbound == nullptr) return false;
    const QString name = !ent->name.isEmpty() ? ent->name : ent->outbound->name;
    const QString type = ent->type.isEmpty() ? QString() : ent->type;
    const QString addr = ent->outbound->server;
    for (const auto &rule : rules) {
        switch (rule.field) {
            case Field::Name:
                if (textMatches(name, rule) || textMatches(ent->outbound->name, rule)) return true;
                break;
            case Field::Type:
                if (textMatches(type, rule)) return true;
                break;
            case Field::Addr:
                if (textMatches(addr, rule)) return true;
                break;
            case Field::Any:
                if (textMatches(name, rule) || textMatches(ent->outbound->name, rule)
                    || textMatches(type, rule) || textMatches(addr, rule)) return true;
                break;
        }
    }
    return false;
}

} // namespace ServerFilter
} // namespace Subscription
