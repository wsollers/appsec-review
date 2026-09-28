/* Bounded Joern CPG projection used by the accepted AppSec evidence producer.
 * Target text is data.  The script emits JSONL records only; Python validates,
 * redacts, binds and limits them before publication.
 */

import java.io.PrintWriter
import scala.util.Try
import io.shiftleft.semanticcpg.language.locationCreator

def json(value: String): String = {
  val escaped = value.flatMap {
    case '"'  => "\\\""
    case '\\' => "\\\\"
    case '\n' => "\\n"
    case '\r' => "\\r"
    case '\t' => "\\t"
    case c if c < ' ' => f"\\u${c.toInt}%04x"
    case c => c.toString
  }
  s"\"$escaped\""
}

def maybe(value: Option[?]): String = value.map(_.toString).getOrElse("null")

@main def main(inputPath: String, outputPath: String, maxRecords: Int = 50000) = {
  importCode(inputPath)
  val out = new PrintWriter(outputPath, "UTF-8")
  var count = 0
  def emit(fields: Seq[(String, String)]): Unit = {
    if (count >= maxRecords) throw new RuntimeException("CPG record limit exceeded")
    out.println(fields.map { case (key, value) => json(key) + ":" + value }.mkString("{", ",", "}"))
    count += 1
  }
  try {
    cpg.method.l.sortBy(m => (m.filename, m.lineNumber.getOrElse(0), m.fullName)).foreach { m =>
      emit(Seq("kind" -> json("symbol"), "label" -> json("METHOD"), "name" -> json(m.name),
        "full_name" -> json(m.fullName), "caller" -> json(""), "type_name" -> json(m.signature),
        "file" -> json(m.filename), "line" -> maybe(m.lineNumber), "column" -> maybe(m.columnNumber),
        "code" -> json(m.code)))
    }
    cpg.typeDecl.l.sortBy(t => (t.filename, t.lineNumber.getOrElse(0), t.fullName)).foreach { t =>
      emit(Seq("kind" -> json("type"), "label" -> json("TYPE_DECL"), "name" -> json(t.name),
        "full_name" -> json(t.fullName), "caller" -> json(""), "type_name" -> json(t.fullName),
        "file" -> json(t.filename), "line" -> maybe(t.lineNumber), "column" -> maybe(t.columnNumber),
        "code" -> json(t.code)))
    }
    // Some nodes (freeciv21) have no enclosing method/graph; their location/method accessors throw.
    // Skip those nodes rather than lose the whole export.
    def safe(value: => String): String = Try(value).getOrElse("")
    cpg.call.l.filter(c => Try(c.method.fullName).isSuccess).sortBy(c => (safe(c.location.filename), c.lineNumber.getOrElse(0), c.code)).foreach { c =>
      val caller = c.method.fullName
      val lowered = (c.name + " " + c.methodFullName + " " + c.code).toLowerCase
      val memory = Seq("memcpy", "memmove", "strcpy", "strncpy", "malloc", "calloc", "realloc", "free",
        "<operator>.assignment", "<operator>.indirect", "<operator>.index").exists(lowered.contains)
      emit(Seq("kind" -> json(if (memory) "memory-operation" else "call"), "label" -> json("CALL"),
        "name" -> json(c.name), "full_name" -> json(c.methodFullName), "caller" -> json(caller),
        "type_name" -> json(c.typeFullName), "file" -> json(safe(c.location.filename)),
        "line" -> maybe(c.lineNumber), "column" -> maybe(c.columnNumber), "code" -> json(c.code)))
    }
    cpg.identifier.l.filter(i => Try(i.location.filename).isSuccess).sortBy(i => (safe(i.location.filename), i.lineNumber.getOrElse(0), i.name)).foreach { i =>
      emit(Seq("kind" -> json("identifier"), "label" -> json("IDENTIFIER"), "name" -> json(i.name),
        "full_name" -> json(""), "caller" -> json(""), "type_name" -> json(i.typeFullName),
        "file" -> json(safe(i.location.filename)), "line" -> maybe(i.lineNumber), "column" -> maybe(i.columnNumber),
        "code" -> json(i.code)))
    }
  } finally {
    out.close()
  }
  count
}
