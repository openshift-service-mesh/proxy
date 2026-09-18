//! Provides a homogeneous interface to toml_edit's various types, and
//! a traversal interface.
//!
//! toml_edit provides an inhomogeneous interface through `Item`,
//! `Table`, `Value`, `Array`, and various others, which makes
//! traversing the document tree and working with the nodes very
//! difficult.
//!
//! This module introduces a trait providing a homogeneous abstraction
//! over the various types.  Then, it provides a convenient traversal
//! interface.

use std::{
    borrow::Cow,
    fmt,
};

use toml_edit::{
    Array,
    Item,
    Table,
    Value,
};

/// Represents a path in a document tree.
#[derive(Debug, Clone)]
pub struct Path {
    components: Vec<PathComponent>,
}

impl fmt::Display for Path {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, c) in self.components.iter().enumerate() {
            if i > 0 {
                f.write_str(".")?;
            }

            write!(f, "{}", c)?;
        }

        Ok(())
    }
}

impl std::str::FromStr for Path {
    type Err = PathError;

    fn from_str(s: &str) -> PathResult<Self> {
        Ok(Path {
            components: s.split(".").map(PathComponent::from_str)
                .collect::<PathResult<Vec<_>>>()?,
        })
    }
}

impl Path {
    /// Returns the number of path components.
    pub fn len(&self) -> usize {
        self.components.len()
    }

    /// Returns whether the path is empty.
    pub fn is_empty(&self) -> bool {
        self.components.is_empty()
    }

    /// Returns an empty path.
    pub fn empty() -> Path {
        Path {
            components: Vec::new(),
        }
    }

    /// Returns the `idx`th path component, if any.
    pub fn get(&self, idx: usize) -> Option<&PathComponent> {
        self.components.get(idx)
    }

    /// Iterates over the path's components.
    pub fn iter(&self) -> impl Iterator<Item = &PathComponent> {
        self.components.iter()
    }

    /// Appends a path component.
    pub fn push(&mut self, component: PathComponent) {
        self.components.push(component);
    }

    /// Removes and returns the last path component, if any.
    pub fn pop(&mut self) -> Option<PathComponent> {
        self.components.pop()
    }
}

/// A path component.
#[derive(Debug, Clone)]
pub enum PathComponent {
    /// A key name in a map.
    Symbol(String),

    /// An index into an array.
    Index(usize),
}

impl fmt::Display for PathComponent {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            PathComponent::Symbol(s) => write!(f, "{}", s),
            PathComponent::Index(i) =>  write!(f, "{}", i),
        }
    }
}

impl From<usize> for PathComponent {
    fn from(v: usize) -> Self {
        PathComponent::Index(v)
    }
}

impl From<&str> for PathComponent {
    fn from(v: &str) -> Self {
        PathComponent::Symbol(v.into())
    }
}

impl std::str::FromStr for PathComponent {
    type Err = PathError;

    fn from_str(s: &str) -> PathResult<Self> {
        if s.contains('.') {
            return Err(PathError::InvalidPathComponent(
                "must not contain a period (\".\")"));
        }

        if let Ok(i) = s.parse::<usize>() {
            Ok(PathComponent::Index(i))
        } else {
            Ok(PathComponent::Symbol(s.into()))
        }
    }
}

impl PathComponent {
    /// Returns an symbolic key, or returns an error.
    pub fn as_symbol(&self) -> Result<&str> {
        match self {
            PathComponent::Symbol(s) => Ok(s),
            PathComponent::Index(i) => Err(Error::BadSymbol(*i)),
        }
    }

    /// Returns an index, or returns an error.
    pub fn as_index(&self) -> Result<usize> {
        match self {
            PathComponent::Symbol(s) => Err(Error::BadIndex(s.to_string())),
            PathComponent::Index(i) => Ok(*i),
        }
    }
}

/// Result specialization for conversions to path components.
pub type PathResult<T> = std::result::Result<T, PathError>;

/// Errors converting to path components.
#[derive(thiserror::Error, Debug)]
pub enum PathError {
    #[error("invalid path component: {0}")]
    InvalidPathComponent(&'static str),
}

/// A unified interface to `toml_edit`.
pub trait Node: fmt::Debug {
    /// Returns the node's type name.
    fn type_name(&self) -> &'static str;

    /// Returns the node as array, if possible.
    fn as_array(&self) -> Option<&Array>;

    /// Returns the node as mutable array, if possible.
    fn as_array_mut(&mut self) -> Option<&mut Array>;

    /// Returns the node as atomic value, if possible.
    fn as_atomic_value(&self) -> Option<&Value>;

    /// Returns the node as mutable table, if possible.
    fn as_table_mut(&mut self) -> Option<&mut Table>;

    /// Returns a reference to the child denoted by `key`.
    fn get(&self, key: &PathComponent) -> Result<&dyn Node>;

    /// Returns a mutable reference to the child denoted by `key`.
    fn get_mut(&mut self, key: &PathComponent) -> Result<&mut dyn Node>;

    /// Sets the child denoted by `key` to the given value.
    fn set(&mut self, key: &PathComponent, value: Value) -> Result<()>;

    /// Removes the child denoted by `key`.
    fn remove(&mut self, key: &PathComponent) -> Result<()>;

    /// Iterates over the children of this node.
    fn iter<'i>(&'i self) -> Box<(dyn Iterator<Item = (PathComponent, &'i dyn Node)> + 'i)>;

    /// Returns a reference to the node that is reached by traversing
    /// `path` from the current node.
    fn traverse(&self, path: &Path) -> TraversalResult<&dyn Node>
    where
        Self: Sized,
    {
        let mut node: &dyn Node = self as _;
        for (i, pc) in path.iter().cloned().enumerate() {
            let type_name = node.type_name();
            node = node.get(&pc)
                .map_err(|e| e.with_context(path, i, type_name))?;
        }

        Ok(node)
    }

    /// Returns a mutable reference to the node that is reached by
    /// traversing `path` from the current node.
    fn traverse_mut(&mut self, path: &Path) -> TraversalResult<&mut dyn Node>
    where
        Self: Sized,
    {
        let mut node: &mut dyn Node = self as _;
        for (i, pc) in path.iter().cloned().enumerate() {
            let type_name = node.type_name();
            node = node.get_mut(&pc)
                .map_err(|e| e.with_context(path, i, type_name))?;
        }

        Ok(node)
    }
}

impl Node for Item {
    fn type_name(&self) -> &'static str {
        self.type_name()
    }

    fn as_array(&self) -> Option<&Array> {
        match self {
            Item::Value(v) => v.as_array(),
            | Item::None
                | Item::Table(_)
                | Item::ArrayOfTables(_) => None,
        }
    }

    fn as_array_mut(&mut self) -> Option<&mut Array> {
        match self {
            Item::Value(v) => v.as_array_mut(),
            | Item::None
                | Item::Table(_)
                | Item::ArrayOfTables(_) => None,
        }
    }

    fn as_atomic_value(&self) -> Option<&Value> {
        match self {
            Item::Value(v) => v.as_atomic_value(),
            | Item::None
                | Item::Table(_)
                | Item::ArrayOfTables(_) => None,
        }
    }

    fn as_table_mut(&mut self) -> Option<&mut Table> {
        match self {
            Item::Table(t) => Some(t),
            | Item::None
                | Item::Value(_)
                | Item::ArrayOfTables(_) => None,
        }
    }

    fn get(&self, key: &PathComponent) -> Result<&dyn Node> {
        match self {
            Item::None => Err(Error::LookupError("none")),
            Item::Value(v) => v.get(key),
            Item::Table(t) => Node::get(t, key),
            Item::ArrayOfTables(a) => {
                let i = key.as_index()?;
                Ok(a.get(i).ok_or_else(|| Error::OutOfBounds(i, a.len()))?)
            },
        }
    }

    fn get_mut(&mut self, key: &PathComponent) -> Result<&mut dyn Node> {
        match self {
            Item::None => Err(Error::LookupError("none")),
            Item::Value(v) => v.get_mut(key),
            Item::Table(t) => Node::get_mut(t, key),
            Item::ArrayOfTables(a) => {
                let i = key.as_index()?;
                let l = a.len();
                Ok(a.get_mut(i).ok_or_else(|| Error::OutOfBounds(i, l))?)
            },
        }
    }

    fn set(&mut self, key: &PathComponent, value: Value) -> Result<()> {
        match self {
            Item::None => Err(Error::InsertionError("none")),
            Item::Value(v) => v.set(key, value),
            Item::Table(t) => {
                t.insert(key.as_symbol()?, Item::Value(value));
                Ok(())
            },
            Item::ArrayOfTables(_) => {
                // XXX: ArrayOfTabels::insert does not exist.
                Err(Error::InsertionError(self.type_name()))
            },
        }
    }

    fn remove(&mut self, key: &PathComponent) -> Result<()> {
        match self {
            Item::None => Err(Error::RemovalError("none")),
            Item::Value(v) => v.remove(key),
            Item::Table(t) => {
                let s = key.as_symbol()?;
                t.remove(s).ok_or(Error::KeyNotFound(s.into()))?;
                Ok(())
            },
            Item::ArrayOfTables(a) => {
                let i = key.as_index()?;
                let l = a.len();
                if i >= l {
                    return Err(Error::OutOfBounds(i, l));
                }
                a.remove(i);
                Ok(())
            },
        }
    }

    fn iter<'i>(&'i self) -> Box<(dyn Iterator<Item = (PathComponent, &'i dyn Node)> + 'i)> {
        match self {
            Item::None => Box::new(std::iter::empty()),
            Item::Value(v) => v.iter(),
            Item::Table(t) => Node::iter(t),
            Item::ArrayOfTables(a) =>
                Box::new(a.iter().enumerate().map(|(k, v)| (k.into(), &*v as &dyn Node))),
        }
    }
}

impl Node for Table {
    fn type_name(&self) -> &'static str {
        "table"
    }

    fn as_array(&self) -> Option<&Array> {
        None
    }

    fn as_array_mut(&mut self) -> Option<&mut Array> {
        None
    }

    fn as_atomic_value(&self) -> Option<&Value> {
        None
    }

    fn as_table_mut(&mut self) -> Option<&mut Table> {
        Some(self)
    }

    fn get(&self, key: &PathComponent) -> Result<&dyn Node> {
        let s = key.as_symbol()?;
        Ok(self.get(s).ok_or_else(|| Error::KeyNotFound(s.into()))?)
    }

    fn get_mut(&mut self, key: &PathComponent) -> Result<&mut dyn Node> {
        let s = key.as_symbol()?;
        Ok(self.get_mut(s).ok_or_else(|| Error::KeyNotFound(s.into()))?)
    }

    fn set(&mut self, key: &PathComponent, value: Value) -> Result<()> {
        let s = key.as_symbol()?;
        self.insert(s, Item::Value(value));
        Ok(())
    }

    fn remove(&mut self, key: &PathComponent) -> Result<()> {
        let s = key.as_symbol()?;
        self.remove(s).ok_or(Error::KeyNotFound(s.into()))?;
        Ok(())
    }

    fn iter<'i>(&'i self) -> Box<(dyn Iterator<Item = (PathComponent, &'i dyn Node)> + 'i)> {
        Box::new(self.iter().map(|(k, v)| (k.into(), &*v as &dyn Node)))
    }
}

impl Node for Value {
    fn type_name(&self) -> &'static str {
        self.type_name()
    }

    fn as_array(&self) -> Option<&Array> {
        match self {
            Value::Array(a) => Some(a),
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_)
                | Value::InlineTable(_) =>
                None,
        }
    }

    fn as_array_mut(&mut self) -> Option<&mut Array> {
        match self {
            Value::Array(a) => Some(a),
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_)
                | Value::InlineTable(_) =>
                None,
        }
    }

    fn as_atomic_value(&self) -> Option<&Value> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Some(self),
            | Value::Array(_)
                | Value::InlineTable(_) =>
                None,
        }
    }

    fn as_table_mut(&mut self) -> Option<&mut Table> {
        None
    }

    fn get(&self, key: &PathComponent) -> Result<&dyn Node> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Err(Error::LookupError(self.type_name())),
            Value::Array(a) => {
                let i = key.as_index()?;
                Ok(a.get(i).ok_or_else(|| Error::OutOfBounds(i, a.len()))?)
            },
            Value::InlineTable(t) => {
                let s = key.as_symbol()?;
                Ok(t.get(s).ok_or_else(|| Error::KeyNotFound(s.into()))?)
            },
        }
    }

    fn get_mut(&mut self, key: &PathComponent) -> Result<&mut dyn Node> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Err(Error::LookupError(self.type_name())),
            Value::Array(a) => {
                let i = key.as_index()?;
                let l = a.len();
                Ok(a.get_mut(i).ok_or_else(|| Error::OutOfBounds(i, l))?)
            },
            Value::InlineTable(t) => {
                let s = key.as_symbol()?;
                Ok(t.get_mut(s).ok_or_else(|| Error::KeyNotFound(s.into()))?)
            },
        }
    }

    fn set(&mut self, key: &PathComponent, value: Value) -> Result<()> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Err(Error::InsertionError(self.type_name())),
            Value::Array(a) => {
                let i = key.as_index()?;
                let l = a.len();
                if i >= l {
                    return Err(Error::OutOfBounds(i, l));
                }
                a.replace(i, value);
                Ok(())
            },
            Value::InlineTable(t) => {
                t.insert(key.as_symbol()?, value);
                Ok(())
            },
        }
    }

    fn remove(&mut self, key: &PathComponent) -> Result<()> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Err(Error::RemovalError(self.type_name())),
            Value::Array(a) => {
                let i = key.as_index()?;
                let l = a.len();
                if i >= l {
                    return Err(Error::OutOfBounds(i, l));
                }
                a.remove(i);
                Ok(())
            },
            Value::InlineTable(t) => {
                let s = key.as_symbol()?;
                t.remove(s).ok_or(Error::KeyNotFound(s.into()))?;
                Ok(())
            },
        }
    }

    fn iter<'i>(&'i self) -> Box<(dyn Iterator<Item = (PathComponent, &'i dyn Node)> + 'i)> {
        match self {
            | Value::String(_)
                | Value::Integer(_)
                | Value::Float(_)
                | Value::Boolean(_)
                | Value::Datetime(_) =>
                Box::new(std::iter::empty()),
            Value::Array(a) =>
                Box::new(a.iter().enumerate().map(|(k, v)| (k.into(), &*v as &dyn Node))),
            Value::InlineTable(t) =>
                Box::new(t.iter().map(|(k, v)| (k.into(), &*v as &dyn Node))),
        }
    }
}

/// Result specialization for this module.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors for this module.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("key {0:?} not found")]
    KeyNotFound(String),

    #[error("index {0} is out of bounds")]
    OutOfBounds(usize, usize),

    #[error("cannot index into a {0}")]
    LookupError(&'static str),

    #[error("cannot insert into a {0}")]
    InsertionError(&'static str),

    #[error("cannot remove items from a {0}")]
    RemovalError(&'static str),

    #[error("{0:?} is not a numeric index")]
    BadIndex(String),

    #[error("{0:?} is not a valid symbol")]
    BadSymbol(usize),
}

impl Error {
    /// Adds context to the error, yielding a [`TraversalError`].
    pub fn with_context(self, path: &Path, i: usize, type_name: &'static str)
                        -> TraversalError
    {
        let p = Path {
            components: path.components[..i].iter().cloned().collect(),
        };
        match self {
            Error::KeyNotFound(k) => TraversalError::KeyNotFound(p, k),
            Error::OutOfBounds(i, l) => TraversalError::OutOfBounds(p, i, l),
            Error::LookupError(t) => match &path.components[i] {
                PathComponent::Symbol(s) =>
                    TraversalError::KeyLookupBadType(p, s.into(), t),
                PathComponent::Index(i) =>
                    TraversalError::IndexLookupBadType(p, *i, t)
            },
            Error::BadIndex(s) =>
                TraversalError::KeyLookupBadType(p, s, type_name),
            Error::BadSymbol(i) =>
                TraversalError::IndexLookupBadType(p, i, type_name),
            Error::InsertionError(_) | Error::RemovalError(_) =>
                unreachable!("not applicable for traversals"),
        }
    }
}

/// Result specialization for traversal errors.
pub type TraversalResult<T> = std::result::Result<T, TraversalError>;

/// Errors traversing the document tree.
#[derive(thiserror::Error, Debug)]
pub enum TraversalError {
    #[error("Tried to look up {1:?}{path}, \
             but it does not exist",
            path=Self::fmt_path("in", &.0))]
    KeyNotFound(Path, String),

    #[error("Tried to get the item at index {1}{path}, \
             but there are only {2} items",
            path=Self::fmt_path("from", &.0))]
    OutOfBounds(Path, usize, usize),

    #[error("Tried to look up {1:?}{path}, \
             but the latter is a {2}, not a table",
            path=Self::fmt_path("in", &.0))]
    KeyLookupBadType(Path, String, &'static str),

    #[error("Tried to get the item at index {1}{path}, \
             but the latter is a {2}, not an array",
            path=Self::fmt_path("from", &.0))]
    IndexLookupBadType(Path, usize, &'static str),
}

impl TraversalError {
    /// Formats a position in the document tree for use in error
    /// messages.
    fn fmt_path(preposition: &'static str, p: &Path) -> Cow<'static, str> {
        if p.is_empty() {
            "".into()
        } else {
            format!(" {} {}", preposition, p).into()
        }
    }
}
