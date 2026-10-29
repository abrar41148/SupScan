const { Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
        Header, Footer, AlignmentType, HeadingLevel, BorderStyle, WidthType,
        ShadingType, VerticalAlign, PageNumber, LevelFormat } = require("docx");
const fs = require("fs");

const NAVY = "17242C";
const TEAL = "0C6B62";
const RULE = "C5D2D7";
const HEAD_FILL = "E4ECEE";
const ZEBR = "F6FAFB";

const border = { style: BorderStyle.SINGLE, size: 4, color: RULE };
const borders = { top: border, bottom: border, left: border, right: border };
const noBorder = { style: BorderStyle.NONE, size: 0, color: "FFFFFF" };

function p(text, opts = {}) {
  return new Paragraph({
    spacing: { before: opts.before ?? 0, after: opts.after ?? 160, line: 276 },
    children: [new TextRun({ text, font: "Arial", size: 22 })],
  });
}

function h1(text) {
  return new Paragraph({
    heading: HeadingLevel.HEADING_1,
    border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: TEAL, space: 1 } },
    spacing: { before: 280, after: 140 },
    children: [new TextRun({ text, font: "Arial", size: 28, bold: true, color: NAVY })],
  });
}

function cell(text, width, opts = {}) {
  return new TableCell({
    borders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: opts.fill || "FFFFFF", type: ShadingType.CLEAR },
    margins: { top: 60, bottom: 60, left: 80, right: 80 },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      spacing: { before: 0, after: 0 },
      children: [new TextRun({
        text,
        font: "Arial",
        size: opts.size || 18,
        bold: !!opts.bold,
        color: opts.color || NAVY,
      })],
    })],
  });
}

function table(rows, widths) {
  const total = widths.reduce((a, b) => a + b, 0);
  return new Table({
    width: { size: total, type: WidthType.DXA },
    columnWidths: widths,
    rows: rows.map((row, i) => new TableRow({
      cantSplit: true,
      children: row.map((value, j) => cell(value, widths[j], {
        bold: i === 0,
        fill: i === 0 ? HEAD_FILL : (i % 2 === 0 ? ZEBR : "FFFFFF"),
        size: 18,
      })),
    })),
  });
}

const doc = new Document({
  styles: {
    default: { document: { run: { font: "Arial", size: 22 } } },
    paragraphStyles: [
      {
        id: "Heading1",
        name: "Heading 1",
        basedOn: "Normal",
        next: "Normal",
        quickFormat: true,
        run: { font: "Arial", size: 28, bold: true, color: NAVY },
        paragraph: { spacing: { before: 280, after: 140 }, outlineLevel: 0 },
      },
    ],
  },
  numbering: {
    config: [
      {
        reference: "objectives",
        levels: [{
          level: 0,
          format: LevelFormat.DECIMAL,
          text: "%1.",
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
      {
        reference: "gate",
        levels: [{
          level: 0,
          format: LevelFormat.BULLET,
          text: "•",
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
    ],
  },
  sections: [{
    properties: {
      page: {
        size: { width: 12240, height: 15840 },
        margin: { top: 1080, right: 1080, bottom: 1080, left: 1080 },
      },
    },
    headers: {
      default: new Header({
        children: [new Paragraph({
          border: { bottom: { style: BorderStyle.SINGLE, size: 8, color: TEAL, space: 6 } },
          spacing: { after: 120 },
          children: [
            new TextRun({ text: "supply-scan", font: "Arial", size: 18, bold: true, color: TEAL }),
            new TextRun({ text: "   Technical report", font: "Arial", size: 18, color: "5A6C76" }),
          ],
        })],
      }),
    },
    footers: {
      default: new Footer({
        children: [new Paragraph({
          border: { top: { style: BorderStyle.SINGLE, size: 6, color: RULE, space: 6 } },
          spacing: { before: 80 },
          children: [
            new TextRun({ text: "29 October 2026", font: "Arial", size: 16, color: "5A6C76" }),
            new TextRun({ text: "          ", font: "Arial", size: 16 }),
            new TextRun({ children: [PageNumber.CURRENT], font: "Arial", size: 16, color: "5A6C76" }),
            new TextRun({ text: " / ", font: "Arial", size: 16, color: "5A6C76" }),
            new TextRun({ children: [PageNumber.TOTAL_PAGES], font: "Arial", size: 16, color: "5A6C76" }),
          ],
        })],
      }),
    },
    children: [
      new Paragraph({
        spacing: { before: 0, after: 40 },
        children: [new TextRun({ text: "supply-scan", font: "Arial", size: 40, bold: true, color: NAVY })],
      }),
      new Paragraph({
        spacing: { before: 0, after: 80 },
        children: [new TextRun({
          text: "Reporting known-vulnerable dependency versions, and the release that fixes them",
          font: "Arial", size: 24, color: TEAL,
        })],
      }),
      new Paragraph({
        spacing: { before: 0, after: 200 },
        children: [new TextRun({ text: "29 October 2026", font: "Arial", size: 20, color: "5A6C76" })],
      }),

      h1("1. Problem"),
      p("Applications ship code they did not write. A lockfile records the exact releases that were installed, including packages pulled in by other packages. When a public advisory later covers one of those releases, the project stays exposed until someone notices the version and moves past it."),
      p("Reading that lockfile by hand does not scale. A repository can contain several ecosystems, development tools mixed with production libraries, and version ranges that were never resolved. A useful check has to name the package, say whether it is production or development, point at the advisory, and name a release that fixes it. It also has to fail a build when the risk is one the project has agreed to block, and stay quiet when the version was never resolved."),
      p("supply-scan is that check. It reads a git URL or a directory the user already has, inventories resolved versions, asks the Open Source Vulnerabilities (OSV) service, and writes a text report, a JSON report, and an optional HTML copy. A local page runs the same scan."),

      h1("2. Objectives"),
      new Paragraph({
        numbering: { reference: "objectives", level: 0 },
        spacing: { before: 40, after: 80, line: 276 },
        children: [new TextRun({ text: "Report known-vulnerable versions that are written down in the repository, and the release that fixes them.", font: "Arial", size: 22 })],
      }),
      new Paragraph({
        numbering: { reference: "objectives", level: 0 },
        spacing: { before: 40, after: 80, line: 276 },
        children: [new TextRun({ text: "Use one rule for the command line and the page, including the process exit code.", font: "Arial", size: 22 })],
      }),
      new Paragraph({
        numbering: { reference: "objectives", level: 0 },
        spacing: { before: 40, after: 80, line: 276 },
        children: [new TextRun({ text: "Keep development-only findings visible without failing a default build, and never give malware that exception.", font: "Arial", size: 22 })],
      }),
      new Paragraph({
        numbering: { reference: "objectives", level: 0 },
        spacing: { before: 40, after: 160, line: 276 },
        children: [new TextRun({ text: "Let a person mark a finding as seen without letting that mark hide the finding from continuous integration.", font: "Arial", size: 22 })],
      }),

      h1("3. Scope"),
      p("The scanner reads lockfiles and a few manifests. It covers npm (package-lock.json, pnpm-lock.yaml, yarn.lock, and a bare package.json), Maven (pom.xml, gradle.lockfile, and libs.versions.toml), Packagist (composer.lock), Pub (pubspec.lock and pubspec.yaml), RubyGems (Gemfile.lock and Gemfile), Go (go.mod), Python (requirements files, uv.lock, poetry.lock, and pyproject.toml), and crates.io (Cargo.lock and Cargo.toml)."),
      p("A version is queried only when it is a concrete release from a registry the matcher knows. A range, a git checkout, a path dependency, or a version that is not written in the repo becomes an unchecked row and is not sent to OSV. The scanner does not install packages and does not run npm, pip, Cargo, Go, Composer, Bundler, pub, Gradle, or Maven."),
      p("Out of scope, by design: reachability of the vulnerable function, license checks, typosquat detection beyond OSV malware ids, signatures, opening an upgrade pull request, SARIF, accounts, and a schedule. Continuous integration is expected to run the command and read the exit code."),

      h1("4. Approach"),
      p("The work is a straight pipeline. Acquire the tree, inventory packages, match them to advisories, and render a report."),
      p("Acquisition accepts a local directory or a remote git URL. A remote URL is checked against an allowlist, cloned with a git argument list into a temporary directory, and that directory is deleted when the scan finishes. A local directory is never deleted."),
      p("Inventory walks the tree and parses the files above. Where a lock exists, it wins over a looser manifest in the same directory. Direct and development labels come from the graph or from the manifest that named the dependency, not only from a flag on the locked row. For npm, a package reached only through devDependencies is development even when its own lock entry omits dev, and a package also reached from a production dependency stays production."),
      p("Matching sends ecosystem, name, and version to OSV. Full advisory bodies are fetched together, up to eight at a time, and both the query and the body are cached for 24 hours. The tool drops withdrawn advisories, scores a CVSS v3 vector when one is present, and orders fixed versions the way that ecosystem orders them. The printed recommendation is the highest fix that clears the findings it can compare. Malware ids, those beginning with MAL-, are labelled and sorted first."),
      p("The report is one snapshot: target, commit, branch, and packages. Text, JSON, and HTML are three views of that snapshot. The exit code is a fourth view of the same packages, shared by the command and the page."),

      h1("5. Architecture"),
      p("One pipeline serves both surfaces. run.py is the shared entry. The command calls collect. The page calls run_scan for a path or URL and run_tree for files the browser posted. Saved scans and the ignore list live under the user cache directory, next to the OSV cache, not in the repository."),
      table([
        ["Stage", "Module", "Result"],
        ["Acquire", "acquire.py", "Local directory, or a temp clone of an allowed git URL"],
        ["Inventory", "inventory.py", "Package rows from lockfiles and manifests"],
        ["Match", "match.py", "OSV advisories, severity, and one recommended fix"],
        ["Report", "report.py", "Text, JSON, HTML, and the process exit code"],
      ], [1800, 2200, 6080]),
      new Paragraph({ spacing: { before: 120, after: 160 }, children: [] }),
      p("The page (supply_scan.serve and gui/index.html) binds to 127.0.0.1 only. It can list remote branches, run a scan, store the result, compare two saved scans, and record an ignore. Comparison uses ecosystem and name as identity. The version is what changed, so an advisory that is still present on another version of the same package is not treated as gone."),

      h1("6. Implementation"),
      p("The project is a Python package, supply_scan, with no third-party dependencies. pyproject.toml requires Python 3.11 and exposes the console script supply-scan. Tests are unittest in tests/test_scan.py and stay offline. A live OSV call is a manual check."),
      p("Exit codes, from exit_code in report.py:"),
      table([
        ["Code", "When"],
        ["0", "No failing finding remains."],
        ["1", "Malware, or a critical or high production finding. With --strict, development findings and medium severity also fail."],
        ["2", "Acquisition or matching failed, such as a rejected URL or a missing directory."],
      ], [1200, 8880]),
      new Paragraph({ spacing: { before: 120, after: 80 }, children: [] }),
      p("Unchecked rows do not fail the process. They are printed so a missing lock is visible. The ignore list is a JSON file of ecosystem, name, version, and advisory id. The page can hide ignored rows. The exit code still counts them. Acknowledgement is a workflow. The gate is a control."),
      p("Version ordering is ecosystem-specific. npm, Go, crates.io, and Pub follow Semantic Versioning. Packagist follows Composer stability. PyPI follows PEP 440. RubyGems treats a hyphen as a pre-release marker. Maven uses its qualifier order, so 31.1 sorts before 31.1-jre. A version the parser cannot order stays on its own fixed-in line and does not join the single upgrade recommendation."),

      h1("7. Test results"),
      p("Four checks were re-run on 29 October 2026 with Python 3.13. All four passed in 0.093 seconds. The raw log is submission/evidence/unittest.txt. OSV was stubbed, so the results show the rules rather than a live advisory count."),
      table([
        ["Check", "Expected", "Actual"],
        ["lodash 4.17.20, fixes 4.17.21 and 4.17.23", "Recommend 4.17.23; severity stays critical", "Pass"],
        ["High finding on a dev package", "Exit 0, then 1 when strict", "Pass"],
        ["MAL- finding, strict off", "Exit 1", "Pass"],
        ["Ignore saved for GHSA-dev on left-pad 1.2.3", "Exit code still 1", "Pass"],
        ["URL with && calc.exe appended", "AcquireError before any clone", "Pass"],
      ], [4200, 3480, 2400]),
      new Paragraph({ spacing: { before: 140, after: 80 }, children: [] }),
      p("The highest-fix case matters because naming 4.17.21 would leave the package inside the second advisory. The exit-code case matters because malware is not given the development exception. The ignore case matters because a recorded acknowledgement is not a bypass for CI."),

      h1("8. Limitations"),
      p("Resolved versions are the whole detection surface. If the repository only has a range, the row is unchecked and OSV is not asked. The scanner will not run an installer to fill that gap, because an install changes the machine and can run package scripts."),
      p("There is no offline advisory database. Without a network, the honest result is a package list with every row unchecked. The 24-hour cache reduces repeat lookups. It can also serve an answer that OSV has since changed, until the entry expires or the user passes --no-cache."),
      p("The tool does not decide whether the vulnerable code is reachable, and it does not open the upgrade. Transitive dependencies are included on purpose. A filter that showed only direct dependencies would hide bugs that still ship. That filter is parked, as is a fully offline listing."),
      p("Gradle scripts and Maven builds are not executed. A Gradle 1.+ stays unchecked until a lock names the release. A property in a parent POM is followed only when that parent is in the repository and sets a concrete version. The page is a local viewer, bound to 127.0.0.1, with body size limits. It is not an exposed service."),

      h1("9. Ethics"),
      p("The user chooses the repository. A remote clone is temporary and is deleted after the scan. A directory the user already has is left in place. Advisory data is public OSV data. The report names an upgrade. It does not include exploit steps, payloads, or proof-of-concept code."),
      p("Ignoring a finding is recorded as a human decision and is not allowed to silence the exit code. That keeps a convenience feature from becoming a way to hide a production vulnerability in a build log."),
      p("Scanning a third-party URL still retrieves that repository onto the machine. The operator should have the right to clone it. The tool does not add credentials, tokens, or account data, and this hand-in does not include any."),

      h1("10. References"),
      p("1. Google Open Source Security Team. OSV API, POST /v1/query. https://google.github.io/osv.dev/api/"),
      p("2. FIRST. Common Vulnerability Scoring System v3.1: Specification Document. https://www.first.org/cvss/v3.1/specification-document"),
      p("3. OpenSSF. OSV Schema. https://ossf.github.io/osv-schema/"),
      p("4. npm. package-lock.json. https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json"),
      p("5. Semantic Versioning 2.0.0. https://semver.org/"),
      p("6. PEP 440, Version Identification and Dependency Specification. https://peps.python.org/pep-0440/"),
      p("7. Composer. Versions and constraints. https://getcomposer.org/doc/articles/versions.md"),
      p("8. Apache Maven. Version order specification. https://maven.apache.org/pom.html#version-order-specification"),
    ],
  }],
});

Packer.toBuffer(doc).then((buffer) => {
  const out = require("path").join(__dirname, "..", "technical-report.docx");
  fs.writeFileSync(out, buffer);
  console.log("wrote", out, buffer.length);
});
