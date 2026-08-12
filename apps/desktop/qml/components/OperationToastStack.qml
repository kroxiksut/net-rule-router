// Container for OperationToast cards.
//
// Owns the ToastStackModel and lays out one OperationToast per row,
// stacked vertically with the newest entry at the bottom (because
// `ToastStackModel.push` uses `ListModel.append`). The host
// (Main.qml) anchors the container to the bottom-right of the
// ApplicationWindow content area; because the container's height
// tracks `column.implicitHeight`, as new entries arrive the stack
// grows upward away from the bottom anchor — the running toast
// stays pinned to the corner while older ones rise above it.
//
// The container exposes:
//   * `model` — the ToastStackModel instance to drive from
//     `handlePushEvent("mutation-progress")` in Main.qml. Callers
//     should `push` / `settle` against `stack.model`.
//   * `theme`, `ownerRoot` — wiring forwarded to each
//     OperationToast.
//
// Width is fixed to the toast width so all rows align right-edge
// flush; height is implicit (sums child heights + spacing).

import QtQuick 2.15
import QtQuick.Layouts 1.15

Item {
    id: root

    required property QtObject theme
    required property var ownerRoot

    // Bound to ApplicationWindow lifecycle. Exposing the model lets
    // the host call `stack.model.push(...)` / `stack.model.settle(...)`.
    property alias model: toastModel

    width: 380
    implicitHeight: column.implicitHeight
    height: implicitHeight

    visible: toastModel.count > 0

    ToastStackModel { id: toastModel }

    Column {
        id: column
        width: parent.width
        spacing: theme.spacingSm

        Repeater {
            model: toastModel
            delegate: OperationToast {
                // A delegate that declares required properties stops
                // receiving `model` as a context property, so the row
                // has to be required too or every role reads undefined.
                required property var model

                width: column.width
                theme: root.theme
                ownerRoot: root.ownerRoot
                rowId: model.id
                kind: model.kind
                phase: model.phase
                errorCode: model.errorCode
                onDismissRequested: function(id) { toastModel.dismissById(id) }
            }
        }
    }
}
