import QtQuick
import QtTest
import "../../../qml/components" as Product
import "../../../qml/theme" as ProductTheme

Item {
    id: fixture
    width: 640
    height: 540
    property var words: ({})
    property var trayWords: ({})
    property var prompt: null
    function lookup(catalogue, key) {
        var value = catalogue
        var parts = key.split(".")
        for (var i = 0; i < parts.length; i++) {
            if (value === null || value === undefined) return undefined
            value = value[parts[i]]
        }
        return value
    }
    function text(key) {
        var value = lookup(trayWords, key)
        if (typeof value !== "string") value = lookup(words, key)
        if (typeof value !== "string") throw new Error("Missing locale text: " + key)
        return value
    }
    function config(rows, merged) {
        var body = text("tray.auto-rules.body-http-path") + "\n"
            + text("tray.auto-rules.route-line-secondary") + "\n"
            + text("tray.auto-rules.unchecked-declined")
        if (merged) body += "\n" + text("tray.auto-rules.new-rows-pending")
        return {
            titleText: text("tray.auto-rules.title-http-path"), bodyText: body,
            items: rows, selectable: true, preCheckedKeys: [],
            listAccessibleName: text("tray.auto-rules.list-accessible-name"),
            primaryAction: {label: text("tray.auto-rules.action.accept"), actionId: "auto-rules-accept", accent: true},
            secondaryAction: {label: text("tray.auto-rules.action.always"), actionId: "auto-rules-always", keepsOpen: true},
            tertiaryAction: {label: text("action.details"), actionId: "auto-rules-details", keepsOpen: true},
            dismissAction: {label: text("tray.auto-rules.action.dismiss"), actionId: "auto-rules-dismiss"},
            dismissActionId: "auto-rules-later", autoRetireMs: 0
        }
    }
    function row(key, hostname) {
        return {key: key, primaryText: hostname,
            secondaryText: text("tray.auto-rules.reach.confirmed"),
            detailText: text("tray.auto-rules.signal.http-path-reachability") + "\n"
                + text("tray.auto-rules.detail-match-kind.exact")}
    }
    function verifyGeometry(item) {
        if (item.visible && typeof item.text === "string") {
            var point = item.mapToItem(prompt.contentItem, 0, 0)
            var inside = point.x >= 0 && point.y >= 0
                && point.x + item.width <= prompt.width + 1
                && point.y + item.height <= prompt.height + 1
            if (item.text === prompt.bodyText) {
                console.log("TRAY_MERGE_BODY", "y", point.y, "height", item.height,
                    "paintedHeight", item.paintedHeight, "inside", inside,
                    "paintedFits", item.paintedHeight <= item.height + 1)
                checks.verify(item.paintedHeight <= item.height + 1, "The body text must fit its own scrollable label")
            }
            if (item.checkable === false) {
                console.log("TRAY_MERGE_ACTION", JSON.stringify(item.text),
                    "x", point.x, "y", point.y, "width", item.width, "height", item.height,
                    "inside", inside)
                checks.verify(inside, "Action remains inside the visible prompt: " + item.text)
            }
        }
        var children = item.children || []
        for (var i = 0; i < children.length; i++) verifyGeometry(children[i])
    }
    ProductTheme.ThemeTokens {id: tokens; themeMode: "light"; fontScalePercent: 160}
    Component {
        id: promptFactory
        Product.TrayPromptWindow {
            theme: tokens
            width: 600
            copyLabel: fixture.text("action.copy")
            copiedLabel: fixture.text("action.copied")
            closeAccessibleText: fixture.text("action.close")
        }
    }
    TestCase {
        id: checks
        name: "TrayPromptLayout"
        when: windowShown
        function initTestCase() {
            var request = new XMLHttpRequest()
            request.open("GET", Qt.resolvedUrl("../../../../../locales/ru.json"), false)
            request.send()
            verify(request.status === 0 || request.status === 200, "read the frozen actual RU catalogue")
            fixture.words = JSON.parse(request.responseText)
            request = new XMLHttpRequest()
            request.open("GET", Qt.resolvedUrl("../../../../../locales/tray/ru.json"), false)
            request.send()
            verify(request.status === 0 || request.status === 200, "read the actual RU tray catalogue")
            fixture.trayWords = JSON.parse(request.responseText)
            compare(tokens.baseFontSizePx, 22, "160 percent uses the real 22px product font")
        }
        function test_actual_window_keeps_merged_choices_and_actions_reachable() {
            var modes = ["light", "dark"]
            for (var m = 0; m < modes.length; m++) {
                tokens.themeMode = modes[m]
                fixture.prompt = promptFactory.createObject(fixture)
                verify(fixture.prompt !== null, "new real prompt window for each capture")
                var rows = [fixture.row("first", "first.example"), fixture.row("second", "second.example")]
                prompt.present(fixture.config(rows, false))
                wait(250)
                prompt._checked = [false, true]
                prompt.detailsExpanded = true
                var serial = prompt.presentationSerial
                rows = rows.concat([fixture.row("new", "himalayas.app")])
                prompt.replaceContent(fixture.config(rows, true))
                wait(400)
                compare(prompt.width, 600)
                compare(prompt._baseFontPx, 22)
                compare(prompt.presentationSerial, serial, "same review, without present or focus reset")
                verify(prompt.detailsExpanded, "expanded details survived")
                compare(JSON.stringify(prompt._checked), "[false,true,false]", "old choice and unchecked newcomer survived")
                fixture.verifyGeometry(prompt.contentItem)
                prompt.retire()
                wait(100)
                prompt.destroy()
                fixture.prompt = null
                wait(100)
            }
            tokens.fontScalePercent = 100
            fixture.prompt = promptFactory.createObject(fixture)
            prompt.width = 460
            var shortNotice = fixture.config([], false)
            shortNotice.titleText = "first.example"
            shortNotice.bodyText = fixture.text("tray.auto-rules.route-line-secondary")
            shortNotice.secondaryAction = null
            shortNotice.tertiaryAction = null
            shortNotice.dismissAction = null
            prompt.present(shortNotice)
            wait(300)
            verify(prompt.height <= 440, "a short normal-scale toast keeps its compact size")
            fixture.verifyGeometry(prompt.contentItem)
            prompt.retire()
            wait(100)
            prompt.destroy()
            fixture.prompt = null
        }
    }
}
