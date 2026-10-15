// Self-test input of the qmllint gate: the missing brace below must be
// reported as a syntax error, or the gate has gone blind.
import QtQuick

Item {
    width: 10

    Rectangle {
        color: "red"
}
