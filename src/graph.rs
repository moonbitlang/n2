use std::hash::Hasher;
use std::os::unix::fs::MetadataExt;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct Hash(u64);

impl Hash {
    pub fn todo() -> Self {
        Hash(0)
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct FileId(usize);
impl FileId {
    fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct BuildId(usize);
impl BuildId {
    fn index(&self) -> usize {
        self.0
    }
}

#[derive(Debug)]
pub struct File {
    pub name: String,
    pub input: Option<BuildId>,
    pub dependents: Vec<BuildId>,
}

#[derive(Debug)]
pub struct FileLoc {
    pub filename: std::rc::Rc<String>,
    pub line: usize,
}
impl std::fmt::Display for FileLoc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(f, "{}:{}", self.filename, self.line)
    }
}

#[derive(Debug)]
pub struct Build {
    pub location: FileLoc,
    pub cmdline: Option<String>,
    pub ins: Vec<FileId>,
    pub explicit_ins: usize,
    pub implicit_ins: usize,
    pub outs: Vec<FileId>,
    pub explicit_outs: usize,
}

const UNIT_SEPARATOR: u8 = 0x1F;

pub struct Graph {
    files: Vec<File>,
    builds: Vec<Build>,
}

impl Graph {
    pub fn new() -> Graph {
        Graph {
            files: Vec::new(),
            builds: Vec::new(),
        }
    }

    pub fn add_file(&mut self, name: String) -> FileId {
        let id = self.files.len();
        self.files.push(File {
            name: name,
            input: None,
            dependents: Vec::new(),
        });
        FileId(id)
    }
    pub fn file(&self, id: FileId) -> &File {
        &self.files[id.index()]
    }

    pub fn add_build(&mut self, build: Build) {
        let id = BuildId(self.builds.len());
        for inf in &build.ins {
            self.files[inf.index()].dependents.push(id);
        }
        for out in &build.outs {
            let f = &mut self.files[out.index()];
            match f.input {
                Some(b) => panic!("double link {:?}", b),
                None => f.input = Some(id),
            }
        }
        self.builds.push(build);
    }
    pub fn build(&self, id: BuildId) -> &Build {
        &self.builds[id.index()]
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
pub enum MTime {
    Missing,
    Stamp(u32),
}

#[derive(Clone, Debug)]
pub struct FileState {
    // used by downstream builds for computing their hash.
    pub mtime: Option<MTime>,
    // hash of input + mtime, used to tell if file is up to date.
    pub hash: Option<Hash>,
}
impl FileState {
    fn empty() -> FileState {
        FileState {
            mtime: None,
            hash: None,
        }
    }
}

pub struct State {
    files: Vec<FileState>,
    builds: Vec<Option<Hash>>,
}

impl State {
    pub fn new(graph: &Graph) -> Self {
        let mut files = Vec::new();
        files.resize(graph.files.len(), FileState::empty());
        let mut builds = Vec::new();
        builds.resize(graph.builds.len(), None);
        State {
            files: files,
            builds: builds,
        }
    }

    pub fn file(&self, id: FileId) -> &FileState {
        &self.files[id.index()]
    }
    pub fn file_mut(&mut self, id: FileId) -> &mut FileState {
        &mut self.files[id.index()]
    }

    pub fn get_hash(&self, id: BuildId) -> Option<Hash> {
        self.builds[id.index()]
    }

    pub fn hash(&mut self, graph: &Graph, id: BuildId) -> Hash {
        match self.get_hash(id) {
            Some(hash) => hash,
            None => {
                let hash = self.do_hash(graph, id);
                self.builds[id.index()] = Some(hash);
                hash
            }
        }
    }

    fn do_hash(&mut self, graph: &Graph, id: BuildId) -> Hash {
        let build = graph.build(id);
        let mut h = std::collections::hash_map::DefaultHasher::new();
        for &id in &build.ins[0..(build.explicit_ins+build.implicit_ins)] {
            h.write(graph.file(id).name.as_bytes());
            let mtime = self.file(id).mtime.unwrap();
            let mtime_int = match mtime {
                MTime::Missing => 0,
                MTime::Stamp(t) => t + 1,
            };
            h.write_u32(mtime_int);
            h.write_u8(UNIT_SEPARATOR);
        }
        h.write(build.cmdline.as_ref().map(|c| c.as_bytes()).unwrap_or(b""));
        Hash(h.finish())
    }

    pub fn stat(&mut self, graph: &Graph, id: FileId) -> std::io::Result<MTime> {
        if self.file(id).mtime.is_some() {
            panic!("redundant stat");
        }
        let name = &graph.file(id).name;
        // TODO: consider mtime_nsec(?)
        let mtime = match std::fs::metadata(name) {
            Ok(meta) => MTime::Stamp(meta.mtime() as u32),
            Err(err) => {
                if err.kind() == std::io::ErrorKind::NotFound {
                    MTime::Missing
                } else {
                    return Err(err);
                }
            }
        };
        self.file_mut(id).mtime = Some(mtime);
        Ok(mtime)
    }
}
