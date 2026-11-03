package demo

val limit = 4 // ANCHOR:none

class Spans(private val name: String) {
    fun count(items: List<String>): Int { // BEGIN:count
        val kept = items.filter { item ->
            item.length > limit // ANCHOR:count
        }
        repeat(2) {
            println(name) // ANCHOR:count
        }
        return kept.size
    } // END:count
}

fun helper(value: Int): Int { // BEGIN:helper
    return value * 2 // ANCHOR:helper
} // END:helper
