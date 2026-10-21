.pragma library
.import "pure.js" as Pure

// "{count} <noun>" in the plural form the active locale's rule family asks for.
// `tr` is the window's translator; `stem` ends with a dot and owns the forms.
function counted(tr, stem, count, fallbackOne, fallbackOther) {
    var category = Pure.pluralCategory(tr("label.plural-rule", "one-other"), count)
    var text = tr(stem + category, "")
    if (text === "") text = tr(stem + "other", count === 1 ? fallbackOne : fallbackOther)
    return text.replace("{count}", String(count))
}
