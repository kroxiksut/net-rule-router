import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

GroupBox {
    property var root
    property string titleKey
    property string titleFallback
    property string noteKey
    property string noteFallback
    title: root.tr(titleKey, titleFallback)
    Layout.fillWidth: true
    Label {
        Layout.fillWidth: true
        wrapMode: Text.WordWrap
        text: root.tr(noteKey, noteFallback)
        color: root.textColor
    }
}
