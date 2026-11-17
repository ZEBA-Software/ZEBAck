//! Zeitplan für Aufträge über die Windows-Aufgabenplanung. Die Aufgabe startet
//! `ZEBack.exe --run-job <Kennung>` im Namen des angemeldeten Benutzers; Adminrechte braucht das nicht.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::config::{SavedJob, ScheduleKind};

/// Name der Aufgabe in der Aufgabenplanung (im Ordner "ZEBack").
pub fn task_name(job_id: u64) -> String {
    format!("ZEBack\\Auftrag-{job_id}")
}

fn escape_xml(text: &str) -> String {
    text.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// Beschreibung der Aufgabe im XML-Format der Aufgabenplanung.
pub fn task_xml(exe: &Path, job: &SavedJob) -> String {
    const DAYS: [&str; 7] = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let (hour, minute) = (job.hour.min(23), job.minute.min(59));
    let calendar = |schedule: &str| {
        format!(
            "<CalendarTrigger>\n      <StartBoundary>2026-01-01T{hour:02}:{minute:02}:00</StartBoundary>\n      <Enabled>true</Enabled>\n      {schedule}\n    </CalendarTrigger>"
        )
    };
    let (trigger, arguments) = match job.schedule {
        ScheduleKind::Weekly => (
            calendar(&format!(
                "<ScheduleByWeek><DaysOfWeek><{} /></DaysOfWeek><WeeksInterval>1</WeeksInterval></ScheduleByWeek>",
                DAYS[usize::from(job.weekday.min(6))]
            )),
            format!("--run-job {}", job.id),
        ),
        // Beim Anstecken: Windows kennt dafür keinen einfachen Auslöser. Die Aufgabe schaut
        // deshalb alle paar Minuten nach, ob das Ziel da ist, und endet sonst sofort wieder.
        ScheduleKind::Plugged => (
            format!(
                "<TimeTrigger>\n      <Repetition>\n        <Interval>PT{PLUG_CHECK_MINUTES}M</Interval>\n        <StopAtDurationEnd>false</StopAtDurationEnd>\n      </Repetition>\n      <StartBoundary>2026-01-01T00:00:00</StartBoundary>\n      <Enabled>true</Enabled>\n    </TimeTrigger>"
            ),
            format!("--run-job {} --if-plugged", job.id),
        ),
        _ => (calendar("<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"), format!("--run-job {}", job.id)),
    };
    let description = tr!(
        "ZEBack-Sicherungsauftrag „{name}“ ({when})",
        "ZEBack backup job “{name}” ({when})",
        name = escape_xml(&job.name),
        when = escape_xml(&job.schedule_text()),
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Author>ZEBack</Author>
    <Description>{description}</Description>
  </RegistrationInfo>
  <Triggers>
    {trigger}
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT24H</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"#,
        command = escape_xml(&exe.display().to_string()),
    )
}

/// Zeitplan "Beim Anstecken": so oft schaut die Aufgabe nach, ob das Ziel da ist.
pub const PLUG_CHECK_MINUTES: u32 = 5;

fn schtasks(args: &[&str]) -> Result<std::process::Output> {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut command = Command::new(PathBuf::from(root).join("System32").join("schtasks.exe"));
    command.args(args).stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.output().context(t!(
        "Die Windows-Aufgabenplanung (schtasks.exe) ließ sich nicht starten",
        "Windows Task Scheduler (schtasks.exe) could not be started"
    ))
}

/// Trägt den Zeitplan des Auftrags ein (oder ersetzt ihn). `exe` ist das Programm, das die
/// Aufgabe startet.
pub fn register(exe: &Path, job: &SavedJob) -> Result<()> {
    if job.schedule == ScheduleKind::Off {
        return remove(job.id);
    }
    // schtasks erwartet die Datei in UTF-16 mit Markierung am Anfang.
    let xml: Vec<u8> = std::iter::once(0xFEFFu16)
        .chain(task_xml(exe, job).encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    let file = crate::util::TempFile::new(std::env::temp_dir().join(format!("zeback-aufgabe-{}-{}.xml", job.id, std::process::id())));
    std::fs::write(file.path(), xml).context(t!(
        "Aufgabenbeschreibung konnte nicht geschrieben werden",
        "The task definition could not be written"
    ))?;
    let path = file.path().display().to_string();
    let output = schtasks(&["/Create", "/TN", &task_name(job.id), "/XML", &path, "/F"])?;
    if !output.status.success() {
        bail!(tr!(
            "Die Windows-Aufgabenplanung hat den Zeitplan abgelehnt: {}",
            "Windows Task Scheduler rejected the schedule: {}",
            crate::sysimage::decode_console(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Entfernt den Zeitplan des Auftrags. Gibt es keinen, ist das kein Fehler.
pub fn remove(job_id: u64) -> Result<()> {
    // Eine Aufgabe unter dem früheren Programmnamen gleich mit entfernen.
    let previous = previous_task_name(job_id);
    if task_exists(&previous) {
        let _ = schtasks(&["/Delete", "/TN", &previous, "/F"]);
    }
    if !exists(job_id) {
        return Ok(());
    }
    let output = schtasks(&["/Delete", "/TN", &task_name(job_id), "/F"])?;
    if !output.status.success() {
        bail!(tr!(
            "Der Zeitplan konnte nicht entfernt werden: {}",
            "The schedule could not be removed: {}",
            crate::sysimage::decode_console(&output.stderr).trim()
        ));
    }
    Ok(())
}

/// Ist für den Auftrag eine Aufgabe eingetragen?
pub fn exists(job_id: u64) -> bool {
    task_exists(&task_name(job_id))
}

fn task_exists(name: &str) -> bool {
    schtasks(&["/Query", "/TN", name]).is_ok_and(|output| output.status.success())
}

/// Name der Aufgabe unter dem früheren Programmnamen (bis Version 0.14 hieß das Programm Packup).
fn previous_task_name(job_id: u64) -> String {
    format!("Packup\\Auftrag-{job_id}")
}

/// Zieht die Zeitpläne des Vorgängers um: Für jeden geplanten Auftrag, der noch eine Aufgabe
/// unter dem alten Namen hat, wird die Aufgabe unter dem neuen Namen eingetragen (sie startet
/// `exe`) und die alte entfernt. Rückgabe: Zahl der umgezogenen Zeitpläne.
pub fn adopt_previous(exe: &Path, jobs: &[SavedJob]) -> usize {
    let mut moved = 0;
    for job in jobs.iter().filter(|job| job.schedule != ScheduleKind::Off) {
        let previous = previous_task_name(job.id);
        if !task_exists(&previous) {
            continue;
        }
        // Erst die neue Aufgabe eintragen, dann die alte entfernen – nie umgekehrt.
        if (exists(job.id) || register(exe, job).is_ok())
            && schtasks(&["/Delete", "/TN", &previous, "/F"]).is_ok_and(|output| output.status.success())
        {
            moved += 1;
        }
    }
    moved
}

#[cfg(test)]
mod tests {
    use super::*;

    fn job(schedule: ScheduleKind) -> SavedJob {
        SavedJob { id: 4, name: "Büro <täglich> & mehr".into(), schedule, weekday: 4, hour: 7, minute: 5, ..SavedJob::default() }
    }

    #[test]
    fn describes_daily_and_weekly_tasks() {
        let exe = Path::new("C:\\Program Files\\ZEBack\\ZEBack.exe");
        let daily = task_xml(exe, &job(ScheduleKind::Daily));
        assert!(daily.contains("<StartBoundary>2026-01-01T07:05:00</StartBoundary>"));
        assert!(daily.contains("<DaysInterval>1</DaysInterval>"));
        assert!(daily.contains("<Command>C:\\Program Files\\ZEBack\\ZEBack.exe</Command>"));
        assert!(daily.contains("<Arguments>--run-job 4</Arguments>"));
        // Sonderzeichen im Namen dürfen das XML nicht zerstören.
        assert!(daily.contains("Büro &lt;täglich&gt; &amp; mehr"));

        let weekly = task_xml(exe, &job(ScheduleKind::Weekly));
        assert!(weekly.contains("<Friday />") && weekly.contains("<WeeksInterval>1</WeeksInterval>"));
        assert_eq!(task_name(4), "ZEBack\\Auftrag-4");

        // Beim Anstecken: alle paar Minuten nachsehen, und nur dann sichern, wenn das Ziel da ist.
        let plugged = task_xml(exe, &job(ScheduleKind::Plugged));
        assert!(plugged.contains("<TimeTrigger>") && plugged.contains("<Interval>PT5M</Interval>"), "{plugged}");
        assert!(plugged.contains("<Arguments>--run-job 4 --if-plugged</Arguments>"));
        assert!(!plugged.contains("CalendarTrigger") && !daily.contains("--if-plugged"));
    }

    /// Trägt wirklich eine Aufgabe "Beim Anstecken" ein oder entfernt sie wieder, nur auf Wunsch:
    /// `ZEBACK_TEST_PLUG=register|remove`, dazu `ZEBACK_TEST_PLUG_EXE` (das Programm, das die
    /// Aufgabe startet). Die Aufgabe gehört zum Auftrag 999998.
    #[test]
    #[ignore]
    fn real_plug_task_registers_or_removes() {
        let Ok(action) = std::env::var("ZEBACK_TEST_PLUG") else { return };
        let test_job = SavedJob { id: 999_998, name: "Selbsttest Anstecken".into(), schedule: ScheduleKind::Plugged, ..SavedJob::default() };
        if action == "register" {
            let exe = std::env::var("ZEBACK_TEST_PLUG_EXE").expect("ZEBACK_TEST_PLUG_EXE");
            register(Path::new(&exe), &test_job).unwrap();
            let details = schtasks(&["/Query", "/TN", &task_name(test_job.id), "/XML"]).unwrap();
            let xml = crate::sysimage::decode_console(&details.stdout);
            assert!(xml.contains("--run-job 999998 --if-plugged") && xml.contains("PT5M"), "{xml}");
        } else {
            remove(test_job.id).unwrap();
            assert!(!exists(test_job.id));
        }
    }

    /// Trägt wirklich eine Aufgabe in die Windows-Aufgabenplanung ein und entfernt sie sofort
    /// wieder. Von Hand starten: `cargo test real_task -- --ignored`.
    #[test]
    #[ignore]
    fn registers_and_removes_a_real_task() {
        let test_job = SavedJob { id: 999_999, name: "Selbsttest".into(), schedule: ScheduleKind::Weekly, weekday: 6, hour: 3, minute: 0, ..SavedJob::default() };
        let exe = std::env::current_exe().unwrap();
        assert!(!exists(test_job.id), "Es gibt schon eine Aufgabe mit der Testkennung");
        register(&exe, &test_job).unwrap();
        let listed = exists(test_job.id);
        let details = schtasks(&["/Query", "/TN", &task_name(test_job.id), "/XML"]).unwrap();
        remove(test_job.id).unwrap();
        assert!(listed);
        assert!(!exists(test_job.id));
        let xml = crate::sysimage::decode_console(&details.stdout);
        assert!(xml.contains("--run-job 999999") && xml.contains("Sunday"), "{xml}");
    }
}
