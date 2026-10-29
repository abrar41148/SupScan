const pptxgen = require("pptxgenjs");
const path = require("path");

const pres = new pptxgen();
pres.defineLayout({ name: "WIDE", width: 13.333, height: 7.5 });
pres.layout = "WIDE";
pres.title = "supply-scan";
pres.author = "supply-scan";
pres.subject = "Known-vulnerable dependency versions, and the release that fixes them";

const INK = "17242C";
const SHEET = "F6FAFB";
const WHITE = "FFFFFF";
const TEAL = "0C6B62";
const TEAL_SOFT = "E5F4F2";
const MUTE = "5A6C76";
const LINE = "C5D2D7";
const CARD = "FFFFFF";
const LIFT = "21333C";
const MINT = "D7F3EE";

function shadow() {
  return { type: "outer", color: "17242C", blur: 10, offset: 2, angle: 135, opacity: 0.08 };
}

function footer(slide, n) {
  slide.addText("supply-scan", {
    x: 0.55, y: 7.08, w: 3, h: 0.28,
    fontFace: "Consolas", fontSize: 11, color: MUTE, margin: 0,
  });
  slide.addText(String(n), {
    x: 11.8, y: 7.08, w: 0.9, h: 0.28,
    fontFace: "Calibri", fontSize: 12, color: MUTE, align: "right", margin: 0,
  });
}

function kicker(slide, text) {
  slide.addText(text, {
    x: 0.55, y: 0.32, w: 8, h: 0.28,
    fontFace: "Consolas", fontSize: 12, color: TEAL, margin: 0, charSpacing: 1.2,
  });
}

// ----- 1. Title -----
{
  const s = pres.addSlide();
  s.background = { color: INK };
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 7.5, fill: { color: TEAL },
  });
  s.addText("SUPPLY-SCAN", {
    x: 0.7, y: 1.55, w: 8, h: 0.32,
    fontFace: "Consolas", fontSize: 14, color: "8ED9CE", margin: 0, charSpacing: 1.6,
  });
  s.addText("Known-vulnerable versions,\nand the release that fixes them.", {
    x: 0.7, y: 2.0, w: 11.4, h: 1.7,
    fontFace: "Georgia", fontSize: 36, color: WHITE, margin: 0,
  });
  s.addText("A local scan of a git URL or a directory. Text, JSON, and a loopback page.\nThe same exit code on the command line and on the screen.", {
    x: 0.7, y: 3.9, w: 10.5, h: 0.75,
    fontFace: "Calibri", fontSize: 18, color: "D5E4E8", margin: 0,
  });
  const stats = [
    ["0", "Nothing failing"],
    ["1", "Fail the build"],
    ["2", "Could not scan"],
  ];
  stats.forEach((pair, i) => {
    const x = 0.7 + i * 3.9;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 5.15, w: 3.55, h: 1.35,
      fill: { color: LIFT }, rectRadius: 0.08,
    });
    s.addText(pair[0], {
      x: x + 0.22, y: 5.28, w: 1.1, h: 1.05,
      fontFace: "Georgia", fontSize: 36, color: "8ED9CE", margin: 0, valign: "middle",
    });
    s.addText(pair[1], {
      x: x + 1.3, y: 5.4, w: 2.05, h: 0.85,
      fontFace: "Calibri", fontSize: 16, color: WHITE, margin: 0, valign: "middle",
    });
  });
  s.addNotes("The problem is old versions sitting in lockfiles after an advisory is published. This tool reads the versions the repo already resolved, asks OSV, and names the upgrade. The rest of the talk is how that decision is made, and how it is stopped from being silenced.");
}

// ----- 2. Problem -----
{
  const s = pres.addSlide();
  s.background = { color: SHEET };
  kicker(s, "PROBLEM");
  s.addText("A lockfile is what actually shipped.", {
    x: 0.55, y: 0.64, w: 12, h: 0.55,
    fontFace: "Georgia", fontSize: 32, color: INK, margin: 0,
  });
  s.addText("Hand review does not survive a repository that mixes languages, tools, and libraries.", {
    x: 0.55, y: 1.28, w: 12, h: 0.38,
    fontFace: "Calibri", fontSize: 16, color: MUTE, margin: 0,
  });
  const cards = [
    ["01", "Mixed on purpose", "Production libraries and development tools sit in the same tree. A high finding in a test runner is not the same decision as one in a library you ship."],
    ["02", "Transitive still ships", "A bug in a package you did not name is still in the build. Hiding those rows would make a narrower report, not a truer one."],
    ["03", "A range is not a version", "package.json can say ^4.17.20. Until a lock names 4.17.20, there is nothing honest to ask OSV about."],
  ];
  cards.forEach((c, i) => {
    const x = 0.55 + i * 4.2;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 1.9, w: 3.95, h: 3.55,
      fill: { color: CARD }, rectRadius: 0.08, shadow: shadow(),
    });
    s.addText(c[0], {
      x: x + 0.28, y: 2.1, w: 3.3, h: 0.45,
      fontFace: "Georgia", fontSize: 22, color: TEAL, margin: 0,
    });
    s.addText(c[1], {
      x: x + 0.28, y: 2.65, w: 3.4, h: 0.7,
      fontFace: "Georgia", fontSize: 20, color: INK, margin: 0,
    });
    s.addText(c[2], {
      x: x + 0.28, y: 3.45, w: 3.4, h: 1.7,
      fontFace: "Calibri", fontSize: 15, color: "2C3E46", margin: 0,
    });
  });
  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.55, y: 5.65, w: 12.2, h: 1.15,
    fill: { color: TEAL_SOFT }, rectRadius: 0.08,
  });
  s.addText("The check has to name the package, the advisory, and a fixed release, then fail the build only for the risk you agreed to block.", {
    x: 0.8, y: 5.8, w: 11.7, h: 0.85,
    fontFace: "Calibri", fontSize: 16, color: INK, margin: 0, valign: "middle",
  });
  footer(s, 2);
  s.addNotes("The motivation is a repeatable check a CI job can run, with the same result on the command line and on the page. Do not promise reachability. The tool reports known versions, not whether the function is called.");
}

// ----- 3. Design -----
{
  const s = pres.addSlide();
  s.background = { color: SHEET };
  kicker(s, "DESIGN");
  s.addText("Four steps. One snapshot.", {
    x: 0.55, y: 0.64, w: 12, h: 0.5,
    fontFace: "Georgia", fontSize: 32, color: INK, margin: 0,
  });
  const steps = [
    ["1", "Acquire", "A local directory, or an allowed git URL cloned into a temp folder and deleted afterwards."],
    ["2", "Inventory", "Lockfiles and manifests become package rows. A lock wins over a looser file beside it."],
    ["3", "Match", "OSV, cached for 24 hours. The highest fix that can be ordered becomes the one upgrade."],
    ["4", "Report", "Text, JSON, HTML, and one exit code. The page calls this same scan."],
  ];
  steps.forEach((step, i) => {
    const y = 1.4 + i * 1.25;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.55, y, w: 12.2, h: 1.1,
      fill: { color: CARD }, rectRadius: 0.08, shadow: shadow(),
    });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.75, y: y + 0.25, w: 0.6, h: 0.6,
      fill: { color: TEAL }, rectRadius: 0.08,
    });
    s.addText(step[0], {
      x: 0.75, y: y + 0.25, w: 0.6, h: 0.6,
      fontFace: "Georgia", fontSize: 20, color: WHITE, align: "center", valign: "middle", margin: 0,
    });
    s.addText(step[1], {
      x: 1.6, y: y + 0.16, w: 3.2, h: 0.78,
      fontFace: "Georgia", fontSize: 20, color: INK, valign: "middle", margin: 0,
    });
    s.addText(step[2], {
      x: 4.7, y: y + 0.18, w: 7.7, h: 0.74,
      fontFace: "Calibri", fontSize: 16, color: "2C3E46", valign: "middle", margin: 0,
    });
  });
  footer(s, 3);
  s.addNotes("Walk the four boxes. Stress that the page is not a second implementation. run.py is shared. A remote clone is deleted. A folder the user already has is not.");
}

// ----- 4. Implementation -----
{
  const s = pres.addSlide();
  s.background = { color: SHEET };
  kicker(s, "IMPLEMENTATION");
  s.addText("Python 3.11. No third-party packages.", {
    x: 0.55, y: 0.64, w: 12, h: 0.5,
    fontFace: "Georgia", fontSize: 32, color: INK, margin: 0,
  });

  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.55, y: 1.4, w: 7.35, h: 5.35,
    fill: { color: CARD }, rectRadius: 0.08, shadow: shadow(),
  });
  s.addText("Ecosystems read from the tree", {
    x: 0.8, y: 1.58, w: 6.8, h: 0.4,
    fontFace: "Georgia", fontSize: 18, color: INK, margin: 0,
  });
  const ecos = [
    ["npm, pnpm, yarn", "package-lock, pnpm-lock, yarn.lock"],
    ["Maven and Gradle", "pom.xml, lock, version catalog"],
    ["Composer, Pub, Ruby", "composer.lock, pubspec, Gemfile.lock"],
    ["Go, Python, Cargo", "go.mod, locks and requirements, Cargo.lock"],
  ];
  ecos.forEach((row, i) => {
    const y = 2.2 + i * 1.05;
    s.addText(row[0], {
      x: 0.85, y, w: 6.7, h: 0.36,
      fontFace: "Calibri", fontSize: 16, color: INK, bold: true, margin: 0,
    });
    s.addText(row[1], {
      x: 0.85, y: y + 0.34, w: 6.7, h: 0.32,
      fontFace: "Calibri", fontSize: 14, color: MUTE, margin: 0,
    });
  });

  const codes = [
    ["0", "Nothing failing", TEAL_SOFT, TEAL],
    ["1", "Malware, or critical/high in production", "F8EBE8", "8C3A32"],
    ["1", "--strict also fails dev and medium", "F8EBE8", "8C3A32"],
    ["2", "Target or lookup could not finish", "EEF2F4", MUTE],
  ];
  codes.forEach((row, i) => {
    const y = 1.4 + i * 1.35;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 8.1, y, w: 4.65, h: 1.2,
      fill: { color: row[2] }, rectRadius: 0.08,
    });
    s.addText(row[0], {
      x: 8.28, y: y + 0.18, w: 0.7, h: 0.84,
      fontFace: "Georgia", fontSize: 28, color: row[3], margin: 0, valign: "middle",
    });
    s.addText(row[1], {
      x: 9.05, y: y + 0.2, w: 3.45, h: 0.8,
      fontFace: "Calibri", fontSize: 15, color: INK, margin: 0, valign: "middle",
    });
  });
  footer(s, 4);
  s.addNotes("Two choices to say out loud. Development-only npm packages are labelled by walking the graph, not by trusting a missing dev flag. Fixed versions are ordered the way that package manager orders them, so the recommendation is one upgrade. Unchecked rows are printed and do not fail the build.");
}

// ----- 5. Results -----
{
  const s = pres.addSlide();
  s.background = { color: SHEET };
  kicker(s, "RESULTS");
  s.addText("Four checks. 0.093 seconds. All passed.", {
    x: 0.55, y: 0.64, w: 12, h: 0.5,
    fontFace: "Georgia", fontSize: 32, color: INK, margin: 0,
  });
  s.addText("29 October 2026, Python 3.13. OSV was stubbed. This is the rule, not a live advisory count.", {
    x: 0.55, y: 1.22, w: 12, h: 0.35,
    fontFace: "Calibri", fontSize: 15, color: MUTE, margin: 0,
  });

  const header = [
    { text: "Check", options: { fill: { color: INK }, color: WHITE, bold: true, align: "left" } },
    { text: "Expected", options: { fill: { color: INK }, color: WHITE, bold: true, align: "left" } },
    { text: "Actual", options: { fill: { color: INK }, color: WHITE, bold: true, align: "left" } },
  ];
  const bodyOpt = { fill: { color: WHITE }, color: INK, align: "left" };
  const altOpt = { fill: { color: "EEF4F5" }, color: INK, align: "left" };
  const pass = { fill: { color: TEAL_SOFT }, color: TEAL, bold: true, align: "left" };
  const passAlt = { fill: { color: "D7EFEA" }, color: TEAL, bold: true, align: "left" };

  function row(a, b, zebra) {
    const left = zebra ? altOpt : bodyOpt;
    const right = zebra ? passAlt : pass;
    return [
      { text: a, options: left },
      { text: b, options: left },
      { text: "Pass", options: right },
    ];
  }

  s.addTable([
    header,
    row("lodash 4.17.20, fixes at 4.17.21 and 4.17.23", "Recommend 4.17.23", false),
    row("High finding, development only", "Exit 0, then 1 if --strict", true),
    row("MAL- finding, strict off", "Exit 1", false),
    row("Ignore saved for GHSA-dev", "Exit code still 1", true),
    row("Git URL ending in && calc.exe", "Rejected before clone", false),
  ], {
    x: 0.55, y: 1.8, w: 12.2, h: 4.4,
    colW: [5.5, 4.7, 2.0],
    border: [
      { pt: 0, color: SHEET },
      { pt: 0, color: SHEET },
      { pt: 0, color: SHEET },
      { pt: 0, color: SHEET },
    ],
    fontFace: "Calibri",
    fontSize: 14,
    color: INK,
    valign: "middle",
    align: "left",
  });
  footer(s, 5);
  s.addNotes("Do not claim a live count of advisories in a public repo. If there is time, run serve.bat on a local fixture. The numbers on this slide come from tests/test_scan.py, written up in submission/test-evidence.md.");
}

// ----- 6. Mitigation -----
{
  const s = pres.addSlide();
  s.background = { color: SHEET };
  kicker(s, "MITIGATION");
  s.addText("The fix is an upgrade, not an exception.", {
    x: 0.55, y: 0.64, w: 12, h: 0.5,
    fontFace: "Georgia", fontSize: 32, color: INK, margin: 0,
  });

  s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.55, y: 1.4, w: 5.9, h: 5.35,
    fill: { color: INK }, rectRadius: 0.08,
  });
  s.addText("EXIT CODE", {
    x: 0.85, y: 1.65, w: 5.2, h: 0.3,
    fontFace: "Consolas", fontSize: 13, color: "8ED9CE", margin: 0, charSpacing: 1.2,
  });
  s.addText("1", {
    x: 0.85, y: 2.05, w: 5.2, h: 1.5,
    fontFace: "Georgia", fontSize: 84, color: WHITE, margin: 0,
  });
  s.addText("An ignore was saved for GHSA-dev on left-pad 1.2.3. The scan still exited 1. Seeing a finding is not the same as clearing it.", {
    x: 0.85, y: 3.7, w: 5.2, h: 1.5,
    fontFace: "Calibri", fontSize: 16, color: "D5E4E8", margin: 0,
  });
  s.addText("Tested 29 October 2026.", {
    x: 0.85, y: 5.85, w: 5.2, h: 0.4,
    fontFace: "Calibri", fontSize: 14, color: "8ED9CE", margin: 0,
  });

  const controls = [
    ["Upgrade", "Two fixes, 4.17.21 and 4.17.23, collapse to one recommendation: 4.17.23."],
    ["URL allowlist", "A clone URL with && calc.exe is rejected. Git is started with an argument list."],
    ["Loopback page", "The server binds 127.0.0.1. Folder uploads drop paths outside the chosen folder."],
  ];
  controls.forEach((c, i) => {
    const y = 1.4 + i * 1.8;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 6.7, y, w: 6.05, h: 1.65,
      fill: { color: CARD }, rectRadius: 0.08, shadow: shadow(),
    });
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 6.92, y: y + 0.28, w: 0.12, h: 1.1,
      fill: { color: TEAL }, rectRadius: 0.04,
    });
    s.addText(c[0], {
      x: 7.25, y: y + 0.22, w: 5.2, h: 0.4,
      fontFace: "Georgia", fontSize: 18, color: INK, margin: 0,
    });
    s.addText(c[1], {
      x: 7.25, y: y + 0.68, w: 5.2, h: 0.75,
      fontFace: "Calibri", fontSize: 14, color: "2C3E46", margin: 0,
    });
  });
  footer(s, 6);
  s.addNotes("Detection is the OSV match. The control we validated is that accepting a finding does not clear CI. The remediation is the recommended version. A later scan compared with the first shows whether that advisory is actually gone. compare_reports uses ecosystem and name as identity.");
}

// ----- 7. Close -----
{
  const s = pres.addSlide();
  s.background = { color: INK };
  s.addShape(pres.shapes.RECTANGLE, {
    x: 0, y: 0, w: 0.18, h: 7.5, fill: { color: TEAL },
  });
  s.addText("LIMITS", {
    x: 0.7, y: 0.38, w: 8, h: 0.28,
    fontFace: "Consolas", fontSize: 12, color: "8ED9CE", margin: 0, charSpacing: 1.2,
  });
  s.addText("Honest when it cannot resolve.\nSilent never, on a production finding.", {
    x: 0.7, y: 0.75, w: 12, h: 1.35,
    fontFace: "Georgia", fontSize: 30, color: WHITE, margin: 0,
  });
  const cols = [
    ["Limits", "No install step, so a range stays unchecked. No offline advisory database. No reachability proof, no pull request, no SARIF."],
    ["Ethics", "The user chooses the repo. Clones are temporary. Advisories are public. The report names an upgrade and does not include exploit steps."],
    ["Left parked", "A direct-only view, because transitive bugs still ship. A fully offline list, which can only mark every row unchecked."],
  ];
  cols.forEach((c, i) => {
    const x = 0.7 + i * 4.1;
    s.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 2.45, w: 3.9, h: 3.55,
      fill: { color: LIFT }, rectRadius: 0.08,
    });
    s.addText(c[0], {
      x: x + 0.25, y: 2.65, w: 3.4, h: 0.45,
      fontFace: "Georgia", fontSize: 20, color: "8ED9CE", margin: 0,
    });
    s.addText(c[1], {
      x: x + 0.25, y: 3.25, w: 3.4, h: 2.4,
      fontFace: "Calibri", fontSize: 15, color: "E4ECEE", margin: 0,
    });
  });
  s.addText("7", {
    x: 11.8, y: 7.08, w: 0.9, h: 0.28,
    fontFace: "Calibri", fontSize: 12, color: "8ED9CE", align: "right", margin: 0,
  });
  s.addNotes("Close on the limit that matters: the tool is honest when it cannot resolve a version, and it will not hide a production finding behind an ignore click. Questions.");
}

pres.writeFile({ fileName: path.join(__dirname, "..", "presentation.pptx") })
  .then(() => console.log("wrote presentation"))
  .catch((err) => {
    console.error(err);
    process.exit(1);
  });
