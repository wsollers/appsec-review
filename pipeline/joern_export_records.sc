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

/* One Joern frontend per language (joern_cpg.frontend_plan). A plain importCode(dir) guesses ONE language
 * for the whole tree, so a multi-language target got only its dominant language (appsec-multi-vuln: C/C++).
 * frontends: ";"-separated entries, each LANG (importCode with that language over the whole tree) or
 * LANG=dir1,dir2 (the frontend binary per sub-project, for frontends that load one project at a time).
 * Empty: the old single guessed import. Each frontend's outcome goes to <outputPath>.frontends.jsonl;
 * one that fails is recorded there and the others still export.
 */
val SEPARATE = Map(  // frontends the console cannot import directly: run the binary, then importCpg
  "CSHARPSRC" -> "/opt/joern-cli/frontends/csharpsrc2cpg/bin/csharpsrc2cpg",
  "RUST" -> "/opt/joern-cli/frontends/rust2cpg/bin/rust2cpg")

@main def main(inputPath: String, outputPath: String, maxRecords: Int = 50000, frontends: String = "",
               joernHome: String = "/opt/joern-cli") = {
  val out = new PrintWriter(outputPath, "UTF-8")
  val status = new PrintWriter(outputPath + ".frontends.jsonl", "UTF-8")
  var count = 0
  def emit(fields: Seq[(String, String)]): Unit = {
    if (count >= maxRecords) throw new RuntimeException("CPG record limit exceeded")
    out.println(fields.map { case (key, value) => json(key) + ":" + value }.mkString("{", ",", "}"))
    count += 1
  }
  def record(language: String, unit: String, state: String, records: Int, detail: String): Unit =
    status.println(Seq("language" -> json(language), "unit" -> json(unit), "status" -> json(state),
      "records" -> records.toString, "detail" -> json(detail.take(300)))
      .map { case (key, value) => json(key) + ":" + value }.mkString("{", ",", "}"))
  def binary(language: String): String = SEPARATE(language).replace("/opt/joern-cli", joernHome)
  try {
    val units: Seq[(String, String)] =
      if (frontends.isEmpty) Seq(("GUESS", ""))
      else frontends.split(";").toSeq.filter(_.nonEmpty).flatMap { entry =>
        entry.split("=", 2) match {
          case Array(language, dirs) => dirs.split(",").toSeq.filter(_.nonEmpty).map(dir => (language, dir))
          case Array(language) => Seq((language, ""))
        }
      }
    units.zipWithIndex.foreach { case ((language, unit), index) =>
      val before = count
      val loaded = Try {
        if (language == "GUESS") importCode(inputPath)
        else if (SEPARATE.contains(language)) {
          val cpgPath = s"$outputPath.$index.cpg.bin"
          val source = if (unit.isEmpty) inputPath else s"$inputPath/$unit"
          val logged = new StringBuilder
          val exit = scala.sys.process.Process(Seq(binary(language), source, "-o", cpgPath))
            .!(scala.sys.process.ProcessLogger(line => logged.append(line).append('\n'), line => logged.append(line).append('\n')))
          if (exit != 0 || !new java.io.File(cpgPath).isFile)
            throw new RuntimeException(s"${language.toLowerCase} frontend exited $exit: " +
              logged.toString.linesIterator.filter(l => l.contains("ERROR") || l.contains("Error")).take(2).mkString(" | "))
          importCpg(cpgPath, s"p$index")
        } else importCode(inputPath, s"p$index", language)
      }
      loaded match {
        case scala.util.Failure(error) =>
          record(language, unit, "FAILED", 0, s"${error.getClass.getSimpleName}: ${error.getMessage}")
        case scala.util.Success(_) =>
          exportRecords(emit, unit)
          record(language, unit, "OK", count - before, "")
          Try(delete)   // free the project before the next frontend
      }
    }
  } finally {
    out.close()
    status.close()
  }
  count
}

/* A per-project frontend names files relative to its project directory (rust: src/main.rs); prefix the
 * project so every path is relative to the checkout like the tree-wide imports. */
def exportRecords(emit: Seq[(String, String)] => Unit, unit: String): Unit = {
  def place(file: String): String =
    if (unit.isEmpty || file.isEmpty || file.startsWith("/") || file.startsWith("<") || file == "N/A") file
    else s"$unit/$file"
  {
    cpg.method.l.sortBy(m => (m.filename, m.lineNumber.getOrElse(0), m.fullName)).foreach { m =>
      emit(Seq("kind" -> json("symbol"), "label" -> json("METHOD"), "name" -> json(m.name),
        "full_name" -> json(m.fullName), "caller" -> json(""), "type_name" -> json(m.signature),
        "file" -> json(place(m.filename)), "line" -> maybe(m.lineNumber), "column" -> maybe(m.columnNumber),
        "code" -> json(m.code)))
    }
    cpg.typeDecl.l.sortBy(t => (t.filename, t.lineNumber.getOrElse(0), t.fullName)).foreach { t =>
      emit(Seq("kind" -> json("type"), "label" -> json("TYPE_DECL"), "name" -> json(t.name),
        "full_name" -> json(t.fullName), "caller" -> json(""), "type_name" -> json(t.fullName),
        "file" -> json(place(t.filename)), "line" -> maybe(t.lineNumber), "column" -> maybe(t.columnNumber),
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
        "type_name" -> json(c.typeFullName), "file" -> json(place(safe(c.location.filename))),
        "line" -> maybe(c.lineNumber), "column" -> maybe(c.columnNumber), "code" -> json(c.code)))
    }
    cpg.identifier.l.filter(i => Try(i.location.filename).isSuccess).sortBy(i => (safe(i.location.filename), i.lineNumber.getOrElse(0), i.name)).foreach { i =>
      emit(Seq("kind" -> json("identifier"), "label" -> json("IDENTIFIER"), "name" -> json(i.name),
        "full_name" -> json(""), "caller" -> json(""), "type_name" -> json(i.typeFullName),
        "file" -> json(place(safe(i.location.filename))), "line" -> maybe(i.lineNumber), "column" -> maybe(i.columnNumber),
        "code" -> json(i.code)))
    }
  }
}
