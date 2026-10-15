//! perd's side of the reference probe's spool: httppost's own lines, and
//! what crons/main's condmv line does with them.
//!
//! perd runs httppost with its stdout appended to data/new/main (the
//! controller's lines end `>> /home/atlas/data/new/main`), so a clock line
//! (9015) lands there, and a minutely condmv line of the same crontab,
//! `condmv -A "RESULT 9901 ongoing" /home/atlas/data/new/main
//! /home/atlas/data/out/main`, appends its marker and moves the file to
//! data/out, where the next post takes it from (`--post-dir
//! /home/atlas/data/out`) and deletes it once the controller has answered
//! OK. Starla keeps those files here, by their path under the spool
//! directory. eperd's results are not files here: they are the results
//! queue, and crons/7's condmv marker goes into it (starla-scheduler).

use std::collections::BTreeMap;
use tokio::sync::Mutex;
use tracing::warn;

/// Where httppost's own lines go: `>> /home/atlas/data/new/main` on each of
/// the controller's httppost lines, which perd's atlas_run opens for the
/// run's stdout (perd.c:1031-1060). Starla does not read the redirection
/// from the line; RIPE's lines name no other file.
pub(crate) const HTTPPOST_OUT: &str = "data/new/main";

/// The directory the main line posts: `--post-dir /home/atlas/data/out`.
const POST_DIR: &str = "data/out/";

/// The most a file of data/new may hold here. The reference's grows until
/// condmv moves it, or dfrm clears a full disk; a file of more than half
/// httppost's default --maxpostsize would be deleted rather than posted. A
/// file that would grow past this loses its oldest lines.
const MAX_FILE: usize = 500_000;

/// A condmv line of perd's crontab as its runs need it: busybox's condmv
/// (coreutils/condmv.c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Condmv {
    /// `-A`
    pub(crate) append: Option<String>,
    /// The file as the line names it
    pub(crate) from: String,
    /// The files moved, under the spool directory
    pub(crate) from_file: String,
    pub(crate) to_file: String,
    /// `-f`
    pub(crate) force: bool,
}

/// The spool's files Starla keeps: path under the spool directory to
/// content, in name order.
#[derive(Default)]
pub(crate) struct Spool {
    files: Mutex<BTreeMap<String, String>>,
}

impl Spool {
    /// Append a line (with its newline) to `file`, as `>>` does.
    pub(crate) async fn append(&self, file: &str, line: &str) {
        let mut files = self.files.lock().await;
        let content = files.entry(file.to_string()).or_default();
        content.push_str(line);
        if content.len() > MAX_FILE {
            let mut cut = content.len() - MAX_FILE;
            while !content.is_char_boundary(cut) {
                cut += 1;
            }
            // whole lines only
            cut = content[cut..]
                .find('\n')
                .map_or(content.len(), |n| cut + n + 1);
            warn!(
                file,
                "Spool file over {MAX_FILE} bytes: its oldest lines dropped"
            );
            content.drain(..cut);
        }
    }

    /// One run of busybox's condmv (coreutils/condmv.c:121-187): nothing if
    /// the destination exists and `-f` was not given; else `-A`'s string,
    /// the time and the file as the line names it are appended — the file
    /// made if there is none, as fopen("a") makes it — and the file moved.
    /// Without `-A`, a file that is not there is not moved. Whether it
    /// moved.
    pub(crate) async fn condmv(&self, line: &Condmv, now: i64) -> bool {
        let mut files = self.files.lock().await;
        if files.contains_key(&line.to_file) && !line.force {
            return false;
        }
        let content = match &line.append {
            Some(append) => {
                let mut content = files.remove(&line.from_file).unwrap_or_default();
                // condmv.c:150-154: `from` as given, not the rebased path
                content.push_str(&format!("{append} {now} {}\n", line.from));
                content
            }
            None => match files.remove(&line.from_file) {
                Some(content) => content,
                None => return false,
            },
        };
        files.insert(line.to_file.clone(), content);
        true
    }

    /// The files a `--post-dir` post takes, in name order.
    pub(crate) async fn outgoing(&self) -> Vec<(String, String)> {
        self.files
            .lock()
            .await
            .iter()
            .filter(|(name, _)| name.starts_with(POST_DIR))
            .map(|(name, content)| (name.clone(), content.clone()))
            .collect()
    }

    /// Delete files: posted, or too big ever to be.
    pub(crate) async fn delete(&self, names: &[String]) {
        let mut files = self.files.lock().await;
        for name in names {
            files.remove(name);
        }
    }

    /// A file's content, if it is there.
    #[cfg(test)]
    pub(crate) async fn file(&self, name: &str) -> Option<String> {
        self.files.lock().await.get(name).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// crons/main's condmv line, as RIPE sent it on 2026-10-14.
    fn crons_main() -> Condmv {
        Condmv {
            append: Some("RESULT 9901 ongoing".into()),
            from: "/home/atlas/data/new/main".into(),
            from_file: "data/new/main".into(),
            to_file: "data/out/main".into(),
            force: false,
        }
    }

    /// condmv.c:150-154 writes `from` as the controller gave it: production
    /// results from probe 1018212's pre-#137 build, and every reference
    /// probe's, read /home/atlas/data/new/main, wherever the spool is.
    #[tokio::test]
    async fn the_marker_names_the_file_as_the_line_does() {
        let spool = Spool::default();
        spool
            .append(
                HTTPPOST_OUT,
                "RESULT 9015 ongoing 1 httppost rtt 1523.46 ms\n",
            )
            .await;
        assert!(spool.condmv(&crons_main(), 1_792_040_000).await);
        assert_eq!(spool.file(HTTPPOST_OUT).await, None);
        assert_eq!(
            spool.outgoing().await,
            [(
                "data/out/main".to_string(),
                "RESULT 9015 ongoing 1 httppost rtt 1523.46 ms\nRESULT 9901 ongoing 1792040000 \
                 /home/atlas/data/new/main\n"
                    .to_string()
            )]
        );
    }

    /// Each minute's run with -A makes a file of its marker alone; while
    /// the last one is not posted, the run moves nothing and appends
    /// nothing ("destination exists"), and httppost's lines wait in
    /// data/new/main.
    #[tokio::test]
    async fn a_run_moves_nothing_onto_a_file_not_yet_posted() {
        let spool = Spool::default();
        assert!(spool.condmv(&crons_main(), 60).await);
        spool
            .append(HTTPPOST_OUT, "RESULT 9015 ongoing 70 x\n")
            .await;
        assert!(!spool.condmv(&crons_main(), 120).await);
        assert_eq!(
            spool.outgoing().await[0].1,
            "RESULT 9901 ongoing 60 /home/atlas/data/new/main\n"
        );
        assert_eq!(
            spool.file(HTTPPOST_OUT).await.as_deref(),
            Some("RESULT 9015 ongoing 70 x\n")
        );

        spool.delete(&["data/out/main".into()]).await;
        assert!(spool.condmv(&crons_main(), 180).await);
        assert_eq!(
            spool.outgoing().await[0].1,
            "RESULT 9015 ongoing 70 x\nRESULT 9901 ongoing 180 /home/atlas/data/new/main\n"
        );

        // -f moves onto it all the same; rename(2) replaces it
        let force = Condmv {
            force: true,
            ..crons_main()
        };
        assert!(spool.condmv(&force, 240).await);
        assert_eq!(
            spool.outgoing().await[0].1,
            "RESULT 9901 ongoing 240 /home/atlas/data/new/main\n"
        );
    }

    /// Without -A, condmv moves the file if it is there (condmv.c:172-177),
    /// and nothing else.
    #[tokio::test]
    async fn without_a_marker_only_a_file_there_moves() {
        let spool = Spool::default();
        let plain = Condmv {
            append: None,
            ..crons_main()
        };
        assert!(!spool.condmv(&plain, 60).await);
        assert!(spool.outgoing().await.is_empty());
        spool.append(HTTPPOST_OUT, "a\n").await;
        assert!(spool.condmv(&plain, 120).await);
        assert_eq!(spool.outgoing().await[0].1, "a\n");
    }

    /// Only data/out is posted; a file moved elsewhere stays.
    #[tokio::test]
    async fn only_data_out_is_posted() {
        let spool = Spool::default();
        let storage = Condmv {
            to_file: "data/storage/main".into(),
            ..crons_main()
        };
        assert!(spool.condmv(&storage, 60).await);
        assert!(spool.outgoing().await.is_empty());
        assert!(spool.file("data/storage/main").await.is_some());
    }

    #[tokio::test]
    async fn a_file_never_moved_keeps_its_newest_lines() {
        let spool = Spool::default();
        let line = format!("{}\n", "x".repeat(99));
        for _ in 0..(MAX_FILE / 100 + 10) {
            spool.append(HTTPPOST_OUT, &line).await;
        }
        let kept = spool.file(HTTPPOST_OUT).await.unwrap();
        assert!(kept.len() <= MAX_FILE, "{}", kept.len());
        assert!(kept.len() > MAX_FILE - 100, "{}", kept.len());
        assert!(kept.starts_with('x') && kept.ends_with("x\n"));
    }
}
