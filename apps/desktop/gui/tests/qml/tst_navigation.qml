import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import QtTest
import "../../../qml/components" as Product
import "../../../qml/theme" as ProductTheme

Item {
    id: canvas
    property var testSettings: ({})
    width: 1100
    height: 760
    property font font: Qt.font({
        family: "Segoe UI",
        pixelSize: tokens.baseFontSizePx
    })
    property var uiTheme: tokens
    property color textColor: tokens.colorText
    property color mutedTextColor: tokens.colorTextMuted
    property color panelColor: tokens.colorPanel
    property color accentColor: tokens.colorAccent
    property bool sidebarCollapsed: false
    property int uiRevision: 1
    property string section: "settings"
    property string settingsCategory: "routing"
    property var prefs: ({
            enhancedFocus: true,
            tooltipsEnabled: true,
            showVirtualMachinesSection: false
        })
    property var context: ({
            windowTitle: "NetRuleRouter"
        })
    property string appIconSource: ""
    property bool updateCheckAvailable: true
    property bool _brokerSessionElevated: false
    property bool rulesNotAppliedToService: false
    property bool rulesNotSavedToFile: false
    property var backendStatus: ({
            kind: "connected"
        })
    property var driftController: ({
            _driftRecheckNow: function (force) {}
        })
    property var autoRuleSuggestionsController: ({
            autoRuleCandidatesPending: 2,
            openAutoRuleSuggestions: function () {
                canvas.requestSectionChange("rule-suggestions");
            }
        })
    property var ruleOverlapsController: ({
            overlaps: [],
            conflicts: [],
            pendingCount: 0,
            open: function () {
                canvas.requestSectionChange("rule-overlaps");
            }
        })
    property var virtualMachinesController: ({
            available: false
        })
    property var reviewFlowController: ({
            _isAppElevated: function () {
                return false;
            },
            revokeAdminApproval: function () {}
        })
    property int transitions: 0
    function requestSectionChange(id) {
        section = id;
        transitions++;
        console.log("NAVIGATED", id);
    }
    function openSettingsCategory(id) {
        settingsCategory = id;
        requestSectionChange("settings");
        console.log("CATEGORY", id);
    }
    function serviceFooterStatusText() {
        return "Service ready";
    }
    function uiIconSource(name) {
        return testSettings.assets + "/icons/ui/" + name + ".svg";
    }
    function uiIconSourceOnAccent(name) {
        return testSettings.assets + "/icons/ui-hc/" + name + ".svg";
    }
    function tr(key, fallback) {
        var v = testSettings.locale;
        var p = key.split(".");
        for (var i = 0; i < p.length; i++) {
            if (v === undefined || v[p[i]] === undefined)
                return fallback;
            v = v[p[i]];
        }
        return typeof v === "string" ? v : fallback;
    }
    function sectionTitle(id) {
        var keys = {
            "interfaces-routes": "section.interfaces-routes",
            rules: "section.rules",
            diagnostics: "section.diagnostics",
            logs: "section.logs",
            settings: "section.settings",
            "conn-trace": "diag.conn-trace.title",
            "outage-blocks": "diag.outage-blocks.title",
            cache: "diag.cache.title"
        };
        return tr(keys[id] || id, id);
    }
    ProductTheme.ThemeTokens {
        id: tokens
        themeMode: testSettings.mode
        fontScalePercent: testSettings.scale
    }
    Rectangle {
        anchors.fill: parent
        color: tokens.colorWindow
    }
    RowLayout {
        anchors.fill: parent
        anchors.margins: 12
        spacing: 12
        Product.NavigationSidebar {
            id: sidebar
            root: canvas
            font: canvas.font
            settingsNavExpanded: true
        }
        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true
            color: tokens.colorBase
            Label {
                anchors.centerIn: parent
                text: canvas.section + " / " + canvas.settingsCategory
                color: canvas.textColor
                font: canvas.font
            }
        }
    }
    function descendants(item, predicate, out) {
        if (predicate(item))
            out.push(item);
        for (var i = 0; i < item.children.length; i++)
            descendants(item.children[i], predicate, out);
    }
    function subButtons() {
        var out = [];
        descendants(sidebar, function (i) {
            return i.visible && i.sectionId !== undefined && i.shell !== undefined && i.contentItem !== undefined;
        }, out);
        return out;
    }
    function textChild(button) {
        var list = [];
        descendants(button.contentItem, function (i) {
            return i.text !== undefined && i.text === button.text;
        }, list);
        return list.length ? list[0] : null;
    }
    TestCase {
        name: "EntireNavigationRail"
        when: windowShown
        function initTestCase() {
            wait(600);
        }
        function capture(name) {
            var image = grabImage(canvas);
            image.save(testSettings.output + "-" + name + ".png");
            console.log("CAPTURE", testSettings.output + "-" + name + ".png");
        }
        function test_01_submenu_geometry() {
            sidebar.settingsNavExpanded = true;
            sidebar.diagnosticsNavExpanded = false;
            wait(250);
            capture("settings");
            var buttons = canvas.subButtons();
            verify(buttons.length >= 8, "settings submenu exists");
            var failures = [];
            for (var i = 0; i < buttons.length; i++) {
                var b = buttons[i], label = canvas.textChild(b), point = b.mapToItem(canvas, 0, 0);
                console.log("GEOMETRY", b.text, "rect", point.x, point.y, b.width, b.height, "implicit", b.implicitWidth, b.implicitHeight, "label", label ? label.width : -1, label ? label.height : -1);
                if (b.width < 40 || !label || label.width < 20)
                    failures.push(b.text + " clickable width=" + b.width + " label width=" + (label ? label.width : -1));
            }
            verify(failures.length === 0, failures.join("; "));
        }
        function test_02_real_mouse_navigates_settings() {
            canvas.settingsCategory = "routing";
            sidebar.settingsNavExpanded = true;
            wait(150);
            var buttons = canvas.subButtons(), target = null;
            for (var i = 0; i < buttons.length; i++)
                if (buttons[i].text === canvas.tr("settings.category.application", "Application"))
                    target = buttons[i];
            verify(target !== null, "application submenu is present");
            var p = target.mapToItem(canvas, Math.max(30, target.width / 2), target.height / 2);
            console.log("REAL_MOUSE", p.x, p.y, "buttonwidth", target.width);
            mouseClick(canvas, p.x, p.y, Qt.LeftButton);
            wait(80);
            compare(canvas.settingsCategory, "application", "clicking the visible application entry must navigate");
            canvas.settingsCategory = "routing";
            target.forceActiveFocus();
            keyClick(Qt.Key_Space);
            wait(80);
            compare(canvas.settingsCategory, "application", "keyboard activation keeps the same destination");
        }
        function test_03_diagnostics_geometry() {
            sidebar.settingsNavExpanded = false;
            sidebar.diagnosticsNavExpanded = true;
            wait(200);
            capture("diagnostics");
            var buttons = canvas.subButtons(), target = null;
            for (var i = 0; i < buttons.length; i++)
                if (buttons[i].sectionId === "outage-blocks")
                    target = buttons[i];
            verify(target !== null);
            var label = canvas.textChild(target);
            console.log("DIAGNOSTICS", target.text, "button", target.width, target.height, "label", label ? label.width : -1, label ? label.implicitWidth : -1);
            verify(target.width > 40 && label && label.width > 20, "long diagnostic entry retains an actual clickable rectangle and readable label");
        }
        function reveal(button) {
            var ancestor = button.parent;
            while (ancestor) {
                if (ancestor.contentY !== undefined && ancestor.contentHeight !== undefined) {
                    var point = button.mapToItem(ancestor.contentItem, 0, 0);
                    ancestor.contentY = Math.max(0, Math.min(point.y - 20, ancestor.contentHeight - ancestor.height));
                    wait(80);
                    return;
                }
                ancestor = ancestor.parent;
            }
        }
        function activate(button, section, category) {
            verify(button.width > 40 && button.height > 20, "entry has a hit rectangle");
            reveal(button);
            canvas.section = "logs";
            canvas.settingsCategory = "none";
            wait(30);
            var point = button.mapToItem(canvas, button.width / 2, button.height / 2);
            verify(point.y > 0 && point.y < canvas.height, "scrolled entry is inside the viewport");
            mouseClick(canvas, point.x, point.y, Qt.LeftButton);
            wait(50);
            compare(canvas.section, section, "mouse activates the visible entry");
            if (category)
                compare(canvas.settingsCategory, category);
            canvas.section = "logs";
            canvas.settingsCategory = "none";
            button.forceActiveFocus();
            keyClick(Qt.Key_Space);
            wait(50);
            compare(canvas.section, section, "Space activates the focused entry");
            if (category)
                compare(canvas.settingsCategory, category);
        }
        function test_04_every_settings_entry_accepts_mouse_and_space_after_scrolling() {
            sidebar.settingsNavExpanded = true;
            sidebar.diagnosticsNavExpanded = false;
            wait(150);
            var buttons = canvas.subButtons();
            var ids = ["application", "notifications", "diagnostics", "traffic", "routing", "service", "presets", "experimental", "updates"];
            compare(buttons.length, ids.length);
            for (var i = 0; i < buttons.length; i++)
                activate(buttons[i], "settings", ids[i]);
            capture("settings-scrolled");
        }
        function test_05_rules_badge_and_diagnostics_accept_real_input() {
            sidebar.settingsNavExpanded = false;
            sidebar.rulesNavExpanded = true;
            sidebar.diagnosticsNavExpanded = false;
            wait(150);
            var buttons = canvas.subButtons(), badge = null;
            for (var i = 0; i < buttons.length; i++) {
                if (buttons[i].sectionId === "rule-suggestions")
                    badge = buttons[i];
                activate(buttons[i], buttons[i].sectionId, "");
            }
            verify(badge !== null);
            compare(badge.badge, 2);
            var count = [];
            canvas.descendants(badge.contentItem, function (item) {
                return item.visible && item.text === "2";
            }, count);
            verify(count.length === 1 && count[0].width > 0, "pending badge is visible beside a readable label");
            var label = canvas.textChild(badge);
            verify(label.width > 20 && label.x + label.width <= count[0].x + 1, "badge and label do not overlap");
            sidebar.rulesNavExpanded = false;
            sidebar.diagnosticsNavExpanded = true;
            wait(150);
            buttons = canvas.subButtons();
            compare(buttons.length, 3);
            for (i = 0; i < buttons.length; i++)
                activate(buttons[i], buttons[i].sectionId, "");
        }
    }
}
