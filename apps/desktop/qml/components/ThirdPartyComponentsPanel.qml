import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../lib/pure.js" as Pure

// Third-party components tab of the Licenses window.
//
// Shows what the product ships from third parties: the attribution their
// licences require, and — for the binaries — a LIVE integrity check of the copy
// on disk (path, SHA-256, who signed it), so the user can confirm the driver is
// the genuine original instead of taking our word for it.
//
// The data comes from the service (`third-party.components.list`), because the
// service owns the platform ports and is the process that actually loads the
// driver. Platforms that ship no third-party binary simply do not return one:
// on Linux/macOS the kernel provides TUN natively, so only the attribution-only
// assets appear and no integrity block is drawn at all.
Item {
    id: panel

    // The ApplicationWindow — shared state (tr, theme, colors, RPC demux).
    property var root

    // Loaded rows, as returned by the service.
    property var components: []
    property bool loading: false
    property string errorText: ""
    property bool loaded: false

    implicitHeight: contentColumn.implicitHeight

    function reload() {
        if (panel.loading)
            return
        var bridge = (typeof nrrNativeBridge !== "undefined") ? nrrNativeBridge : null
        if (bridge === null || typeof bridge.rpcThirdPartyComponentsList !== "function") {
            panel.errorText = root.tr("dialog.third-party.bridge-unavailable",
                "Component information is unavailable: no connection to the service.")
            return
        }
        panel.loading = true
        panel.errorText = ""
        var corr = bridge.rpcThirdPartyComponentsList()
        if (!corr) {
            panel.loading = false
            return
        }
        root.rpc.registerRpcCallback(corr, function(ok, payload, errorCode, errorMessage) {
            panel.loading = false
            panel.loaded = true
            if (!ok) {
                panel.errorText = root.tr("dialog.third-party.load-failed",
                    "Could not read component information: ")
                    + root.ipcErrorLabel(String(errorCode || "unknown"))
                return
            }
            panel.components = (payload && payload.components) || []
        })
    }

    function _verdictLabel(verdict) {
        if (verdict === "genuine")
            return root.tr("dialog.third-party.verdict-genuine", "Genuine")
        if (verdict === "untrusted")
            return root.tr("dialog.third-party.verdict-untrusted", "Does not match")
        if (verdict === "missing")
            return root.tr("dialog.third-party.verdict-missing", "Not installed")
        return root.tr("dialog.third-party.verdict-not-applicable", "Attribution only")
    }

    function _verdictColor(verdict) {
        if (verdict === "genuine")
            return root.uiTheme.colorSuccess
        if (verdict === "untrusted")
            return root.uiTheme.colorDanger
        if (verdict === "missing")
            return root.uiTheme.colorWarning
        return root.uiTheme.colorTextMuted
    }

    function _verdictNote(verdict) {
        if (verdict === "genuine")
            return root.tr("dialog.third-party.verdict-genuine-note",
                "The file on disk matches the build shipped with the product and carries a valid signature from its publisher.")
        if (verdict === "untrusted")
            return root.tr("dialog.third-party.verdict-untrusted-note",
                "The file on disk is not the build shipped with the product, or its signature could not be confirmed. Reinstall the product.")
        if (verdict === "missing")
            return root.tr("dialog.third-party.verdict-missing-note",
                "The component is not installed, so the feature that needs it is unavailable. Everything else keeps working.")
        return ""
    }

    function _signatureLabel(signature) {
        var status = (signature || {}).status || ""
        var detail = (signature || {}).detail || ""
        if (status === "valid")
            return root.tr("dialog.third-party.signature-valid", "Signed by") + " " + detail
        if (status === "signer-mismatch")
            return root.tr("dialog.third-party.signature-signer-mismatch", "Signed by someone else:") + " " + detail
        if (status === "invalid")
            return root.tr("dialog.third-party.signature-invalid", "Signature is not valid")
        if (status === "unsigned")
            return root.tr("dialog.third-party.signature-unsigned", "Not signed")
        return root.tr("dialog.third-party.signature-not-checked", "Signature was not checked")
    }

    function _featureLabel(slug) {
        if (slug === "fake-ip")
            return root.tr("dialog.third-party.feature.fake-ip", "Per-site virtual addresses (fake-IP)")
        if (slug === "user-interface")
            return root.tr("dialog.third-party.feature.user-interface", "Application interface")
        return root.tr("third-party.feature." + String(slug), String(slug))
    }

    function _copy(text) {
        if (typeof nrrNativeBridge !== "undefined"
                && typeof nrrNativeBridge.copyToClipboard === "function") {
            nrrNativeBridge.copyToClipboard(String(text))
            root.statusLine = root.tr("status.copied-to-clipboard", "Copied to clipboard.")
        }
    }

    ColumnLayout {
        id: contentColumn
        anchors.left: parent.left
        anchors.right: parent.right
        spacing: root.uiTheme.spacingMd

        Label {
            Layout.fillWidth: true
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("dialog.third-party.intro",
                "Components from other authors that are shipped with the product. For executable components the application checks the copy on this computer and shows what it found.")
        }

        Label {
            Layout.fillWidth: true
            visible: panel.errorText !== ""
            color: root.uiTheme.colorDanger
            wrapMode: Text.WordWrap
            text: panel.errorText
        }

        Label {
            Layout.fillWidth: true
            visible: panel.loading
            color: root.mutedTextColor
            text: root.tr("dialog.third-party.loading", "Checking components…")
        }

        Repeater {
            model: panel.components
            delegate: Frame {
                id: componentCard
                required property var modelData
                Layout.fillWidth: true
                padding: root.uiTheme.spacingSm
                background: CardSurface { theme: root.uiTheme; cornerRadius: root.uiTheme.radiusSm }

                readonly property bool isBinary: componentCard.modelData.kind === "binary"

                ColumnLayout {
                    anchors.left: parent.left
                    anchors.right: parent.right
                    spacing: root.uiTheme.spacingXs

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm

                        Label {
                            color: root.textColor
                            font.bold: true
                            text: String(componentCard.modelData.displayName || "")
                        }
                        Label {
                            color: root.mutedTextColor
                            text: String(componentCard.modelData.version || "")
                        }
                        Item { Layout.fillWidth: true }

                        // Verdict chip — only meaningful for binaries; assets
                        // carry no integrity claim at all.
                        Rectangle {
                            visible: componentCard.isBinary
                            radius: root.uiTheme.radiusSm
                            implicitHeight: verdictLabel.implicitHeight + root.uiTheme.spacingXs
                            implicitWidth: verdictLabel.implicitWidth + root.uiTheme.spacingMd
                            readonly property color statusColor: panel._verdictColor(componentCard.modelData.verdict)
                            color: Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.16)
                            border.width: 1
                            border.color: Qt.rgba(statusColor.r, statusColor.g, statusColor.b, 0.55)
                            Label {
                                id: verdictLabel
                                anchors.centerIn: parent
                                color: parent.statusColor
                                font.pixelSize: root.uiTheme.baseFontSizePx - 1
                                text: panel._verdictLabel(componentCard.modelData.verdict)
                            }
                            Accessible.role: Accessible.StaticText
                            Accessible.name: verdictLabel.text
                        }
                    }

                    Label {
                        Layout.fillWidth: true
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        text: root.tr("dialog.third-party.publisher", "Author") + ": "
                            + String(componentCard.modelData.publisher || "")
                            + "  ·  " + root.tr("label.license", "License") + ": "
                            + String(componentCard.modelData.licenseName || "")
                    }

                    Label {
                        Layout.fillWidth: true
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        text: root.tr("dialog.third-party.required-for", "Used for") + ": "
                            + panel._featureLabel(componentCard.modelData.requiredFor)
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: componentCard.isBinary && panel._verdictNote(componentCard.modelData.verdict) !== ""
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: panel._verdictNote(componentCard.modelData.verdict)
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: componentCard.isBinary
                        color: root.mutedTextColor
                        wrapMode: Text.WordWrap
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: panel._signatureLabel(componentCard.modelData.signature)
                    }

                    Label {
                        Layout.fillWidth: true
                        visible: componentCard.isBinary && String(componentCard.modelData.path || "") !== ""
                        color: root.mutedTextColor
                        elide: Text.ElideMiddle
                        font.pixelSize: root.uiTheme.baseFontSizePx - 1
                        text: root.tr("dialog.third-party.file", "File") + ": "
                            + String(componentCard.modelData.path || "")
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        visible: componentCard.isBinary && String(componentCard.modelData.sha256 || "") !== ""
                        spacing: root.uiTheme.spacingSm
                        Label {
                            Layout.fillWidth: true
                            color: root.mutedTextColor
                            elide: Text.ElideMiddle
                            font.pixelSize: root.uiTheme.baseFontSizePx - 1
                            text: root.tr("dialog.third-party.checksum", "Checksum (SHA-256)") + ": "
                                + String(componentCard.modelData.sha256 || "")
                        }
                        ThemedButton {
                            theme: root.uiTheme
                            flat: true
                            text: root.tr("action.copy-row", "Copy row")
                            Accessible.name: text
                            onClicked: panel._copy(String(componentCard.modelData.sha256 || ""))
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: root.uiTheme.spacingSm
                        Item { Layout.fillWidth: true }
                        ThemedButton {
                            theme: root.uiTheme
                            flat: true
                            visible: String(componentCard.modelData.homepage || "") !== ""
                            text: root.tr("dialog.third-party.open-homepage", "Author's site")
                            Accessible.name: text
                            onClicked: Pure.openExternalUrl(String(componentCard.modelData.homepage || ""))
                        }
                    }
                }
            }
        }

        Label {
            Layout.fillWidth: true
            visible: panel.loaded && !panel.loading && panel.components.length === 0
                     && panel.errorText === ""
            color: root.mutedTextColor
            wrapMode: Text.WordWrap
            text: root.tr("dialog.third-party.empty",
                "This build ships no components from other authors.")
        }

        RowLayout {
            Layout.fillWidth: true
            ThemedButton {
                theme: root.uiTheme
                text: root.tr("action.refresh", "Refresh")
                enabled: !panel.loading
                Accessible.name: text
                onClicked: panel.reload()
            }
            Item { Layout.fillWidth: true }
        }
    }
}
