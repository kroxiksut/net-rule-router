import QtQuick 2.15
import QtQuick.Controls 2.15

/// Shapes the one tooltip every `ToolTip.text` in this engine shares. A long
/// tip wraps at a readable line length instead of spanning the window, and it
/// never starts left of its control, so it stays off the sidebar.
Item {
    id: shaper
    visible: false

    // Characters per line a paragraph stays comfortable to read at.
    readonly property int measureChars: 70

    FontMetrics {
        id: metrics
    }

    Component.onCompleted: {
        var tip = shaper.ToolTip.toolTip
        if (!tip) return
        metrics.font = Qt.binding(function() { return tip.font })
        tip.implicitWidth = Qt.binding(function() {
            var natural = Math.max(tip.implicitBackgroundWidth + tip.leftInset + tip.rightInset,
                tip.implicitContentWidth + tip.leftPadding + tip.rightPadding)
            var measure = Math.ceil(metrics.averageCharacterWidth * shaper.measureChars)
                + tip.leftPadding + tip.rightPadding
            return Math.min(natural, measure)
        })
        tip.x = Qt.binding(function() {
            return tip.parent ? Math.max(0, (tip.parent.width - tip.implicitWidth) / 2) : 0
        })
    }
}
