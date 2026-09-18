//! Configuration model inspection and manipulation.

use std::collections::BTreeMap;

use anyhow::{Context, Result};

use toml_edit::{
    Item,
    Value,
};

use crate::toml_edit_tree::{
    Error,
    Node,
    Path,
    PathComponent,
    TraversalError,
};

use crate::{
    Sq,
    cli::config,
    config::ConfigFile,
};

mod inspect;

pub fn dispatch(sq: Sq, cmd: config::Command)
                -> Result<()>
{
    match cmd.subcommand {
        config::Subcommands::Get(c) => get(sq, c),
        config::Subcommands::Template(c) => template(sq, c),
        config::Subcommands::Inspect(c) => inspect::dispatch(sq, c),
    }
}

/// Implements `sq config get`.
fn get(sq: Sq, cmd: config::get::Command) -> Result<()> {
    let path = if let Some(name) = &cmd.name {
        name.parse()?
    } else {
        Path::empty()
    };

    // We do two lookups, first in the configuration file, then in the
    // default configuration, and collate the results.
    let mut acc = Default::default();

    // First, look in the configuration.
    let config = sq.config_file.effective_configuration(&sq)?;
    let r0 = Node::traverse(&*config.as_item() as _, &path)
        .map_err(Into::into)
        .and_then(
            |node| collect(&mut acc, path.clone(), node, &|_, _| true));

    // Then, look in the default configuration.  But, we are careful
    // to filter out anything overridden in the actual configuration.
    let default = ConfigFile::default_config(sq.home.as_ref())?;
    let r1 = Node::traverse(&*default.as_item() as _, &path)
        .map_err(Into::into)
        .and_then(
            |node| collect(&mut acc, path, node, &|p, n| {
                // Is this a leaf node?
                let leaf = n.as_atomic_value().is_some()
                    || n.as_array().is_some();

                // Is this set in the config file?
                let is_configured =
                    config.as_item().traverse(p).is_ok();

                // Show or continue traversing if this is either an
                // intermediate node, or the node is absent in the
                // configuration.
                ! leaf || ! is_configured
            }));

    // One of the lookups must be successful.
    r0.or(r1)?;

    // Display sorted and deduplicated results.
    for (k, v) in acc {
        println!("{} = {}", k, v);
    }

    Ok(())
}

/// Collects all nodes below `node` at `path` matching `filter` into
/// `acc`.
pub fn collect<F>(acc: &mut BTreeMap<String, String>,
                  mut path: Path, node: &dyn Node, filter: &F)
                  -> Result<Path>
where
    F: for<'a> Fn(&'a Path, &'a dyn Node) -> bool,
{
    if ! (filter)(&path, node) {
        return Ok(path);
    }

    if let Some(v) = node.as_atomic_value() {
        acc.insert(path.to_string(),
                   v.clone().decorated("", "").to_string());
    } else {
        for (k, v) in node.iter() {
            path.push(k);
            path = collect(acc, path, v, filter)?;
            path.pop();
        }
    }
    Ok(path)
}

/// Implements `sq config set`.
///
/// XXX: Currently, we don't expose this due to problems with
/// toml-edit.  Notably, toml-edit doesn't handle comments well,
/// attaching them as decor to nodes in the document tree.
/// Manipulating the document tree may delete or otherwise disturb the
/// comments in a way that badly distorts the semantics.
#[allow(dead_code)]
fn set(mut sq: Sq, cmd: config::set::Command) -> Result<()> {
    let mut path: Path = cmd.name.parse()?;
    if path.is_empty() {
        return Err(anyhow::anyhow!("NAME must not be empty"));
    };
    let last = path.pop().expect("path is not empty");

    // XXX: Workaround for clap bug, see src/cli/config.rs.
    if cmd.value.is_none() && ! cmd.delete {
        return Err(anyhow::anyhow!("Either VALUE or --delete must be given"));
    }

    let mut config = std::mem::take(&mut sq.config_file);
    let doc = config.as_item_mut();
    if let Some(value) = &cmd.value {
        let value: Value = value.parse().unwrap_or_else(|_| value.into());

        // Like Node::traverse_mut, but we also create intermediate
        // nodes on demand.
        let mut node: &mut dyn Node = doc as _;

        for (i, pc) in path.iter().cloned().enumerate() {
            let type_name = node.type_name();
            if let Err(TraversalError::KeyNotFound(_, _)) =
                node.get_mut(&pc)
                .map_err(|e| e.with_context(&path, i, type_name))
            {
                match path.get(i + 1).unwrap_or(&last) {
                    PathComponent::Symbol(_) => {
                        // Prefer to insert a non-inline table if
                        // possible.
                        if let Some(t) = node.as_table_mut() {
                            t.insert(pc.as_symbol()?,
                                     Item::Table(Default::default()));
                        } else {
                            node.set(&pc,
                                     Value::InlineTable(Default::default()))?;
                        }
                    },
                    PathComponent::Index(_) =>
                        node.set(&pc, Value::Array(Default::default()))?,
                };
            }

            node = node.get_mut(&pc)
                .map_err(|e| e.with_context(&path, i, type_name))?;
        }

        if cmd.add {
            if let Err(Error::KeyNotFound(_)) = node.get_mut(&last) {
                // The node doesn't exist, see if it exists in the
                // default configuration.
                let default = ConfigFile::default_config(sq.home.as_ref())?;
                let v = Node::traverse(&*default.as_item() as _, &path).ok()
                    .and_then(|n| n.get(&last).ok())
                    .and_then(|n| n.as_array())
                    .map(|a| Value::Array(a.clone()))
                    .unwrap_or(Value::Array(Default::default()));

                node.set(&last, v)?;
            }

            let type_name = node.type_name();
            node = node.get_mut(&last)
                .map_err(|e| e.with_context(&path, path.len(), type_name))?;

            let type_name = node.type_name();
            path.push(last);
            if let Some(a) = node.as_array_mut() {
                a.push(value);
            } else {
                return Err(anyhow::anyhow!("Tried to add an element to {}, \
                                            but this is a {} not an array",
                                           path, type_name));
            }
        } else {
            node.set(&last, value)?;
        }
    } else {
        assert!(cmd.delete);
        let node = Node::traverse_mut(&mut *doc as _, &path)?;
        node.remove(&last)?;
    }

    // Verify the configuration.
    config.verify()
        .with_context(|| format!("Failed to {} {:?}",
                                 if cmd.delete { "delete" } else { "set" },
                                 cmd.name))?;

    // The updated config verified, now persist it.
    config.persist(
        sq.home.as_ref().ok_or(anyhow::anyhow!("No home directory given"))?)?;

    Ok(())
}

/// Implements `sq config template`.
fn template(sq: Sq, cmd: config::template::Command) -> Result<()> {
    let mut sink = cmd.output.create_safe(&sq)?;
    ConfigFile::default_template(sq.home.as_ref())?
        .dump(&mut sink)?;

    Ok(())
}
