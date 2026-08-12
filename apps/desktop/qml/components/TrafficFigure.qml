// One "Received 1.2 GB" / "Sent 340 MB" figure with its direction arrow.
//
// The arrow used to be a literal glyph inside the label text, which renders at
// the font's own stroke weight and reads as a speck next to the number. Here it
// is the real icon asset, sized off the theme font so the accessibility text
// scale carries it, and kept out of the label text so a screen reader gets the
// direction as a word instead of a character it may skip.
import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

RowLayout {
    id: figure
    property var theme
    /// Icon asset, normal or high-contrast — pass `root.uiIconSource(...)`.
    property url iconSource
    /// Already-localized direction word ("Received" / "Sent").
    property string label: ""
    /// Already-formatted amount.
    property string value: ""
    property color textColor

    spacing: Math.round(figure.theme.spacingXs)

    Image {
        source: figure.iconSource
        // Sized from the font so text scaling moves the arrow with the number.
        readonly property int px: Math.max(14, Math.round(figure.theme.baseFontSizePx * 1.35))
        sourceSize.width: px
        sourceSize.height: px
        Layout.preferredWidth: px
        Layout.preferredHeight: px
        Layout.alignment: Qt.AlignVCenter
        fillMode: Image.PreserveAspectFit
        smooth: true
        // The label already says "Received"/"Sent"; announcing it twice is noise.
        Accessible.ignored: true
    }
    Label {
        text: figure.label + " " + figure.value
        color: figure.textColor
        Layout.alignment: Qt.AlignVCenter
        Accessible.role: Accessible.StaticText
        Accessible.name: text
    }
}
