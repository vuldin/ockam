use crate::{fmt_info, Terminal, TerminalStream};
use colorful::Colorful;
use console::Term;

#[ockam_core::async_trait]
pub trait ShowCommandTui {
    const ITEM_NAME: &'static str;

    fn cmd_arg_item_name(&self) -> Option<&str>;
    fn terminal(&self) -> Terminal<TerminalStream<Term>>;

    async fn list_items_names(&self) -> miette::Result<Vec<String>>;
    async fn show_single(&self) -> miette::Result<()>;
    async fn show_multiple(&self, items_names: Vec<String>) -> miette::Result<()>;

    async fn show(&self) -> miette::Result<()> {
        let terminal = self.terminal();
        let items_names = self.list_items_names().await?;
        if items_names.is_empty() {
            terminal
                .stdout()
                .plain(fmt_info!("There are no {} to show", Self::ITEM_NAME))
                .write_line()?;
            return Ok(());
        }

        if self.cmd_arg_item_name().is_some() || !terminal.can_ask_for_user_input() {
            self.show_single().await?;
            return Ok(());
        }

        match items_names.len() {
            0 => {
                unreachable!("this case is already handled above");
            }
            1 => {
                self.show_single().await?;
            }
            _ => {
                let selected_item_names = terminal.select_multiple(
                    format!(
                        "Select one or more {} that you want to show",
                        Self::ITEM_NAME
                    ),
                    items_names,
                );
                match selected_item_names.len() {
                    0 => {
                        terminal
                            .stdout()
                            .plain(format!("No {} selected to show", Self::ITEM_NAME))
                            .write_line()?;
                    }
                    1 => {
                        self.show_single().await?;
                    }
                    _ => {
                        self.show_multiple(selected_item_names).await?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[ockam_core::async_trait]
pub trait DeleteCommandTui {
    const ITEM_NAME: &'static str;

    fn cmd_arg_item_name(&self) -> Option<&str>;
    fn cmd_arg_delete_all(&self) -> bool;
    fn cmd_arg_confirm_deletion(&self) -> bool;
    fn terminal(&self) -> Terminal<TerminalStream<Term>>;

    fn list_items_names(&self) -> miette::Result<Vec<String>>;
    async fn delete_single(&self) -> miette::Result<()>;
    async fn delete_multiple(&self, items_names: Vec<String>) -> miette::Result<()>;

    async fn delete(&self) -> miette::Result<()> {
        let terminal = self.terminal();
        let items_names = self.list_items_names()?;
        if items_names.is_empty() {
            terminal
                .stdout()
                .plain(fmt_info!("There are no {} to delete", Self::ITEM_NAME))
                .write_line()?;
            return Ok(());
        }

        if self.cmd_arg_delete_all()
            && terminal.confirmed_with_flag_or_prompt(
                self.cmd_arg_confirm_deletion(),
                format!("Are you sure you want to delete all {}?", Self::ITEM_NAME),
            )?
        {
            self.delete_multiple(items_names).await?;
            return Ok(());
        }

        if self.cmd_arg_item_name().is_some() || !terminal.can_ask_for_user_input() {
            self.delete_single().await?;
            return Ok(());
        }

        match items_names.len() {
            0 => {
                unreachable!("this case is already handled above");
            }
            1 => {
                if terminal.confirmed_with_flag_or_prompt(
                    self.cmd_arg_confirm_deletion(),
                    "Are you sure you want to proceed?",
                )? {
                    self.delete_single().await?;
                }
            }
            _ => {
                let selected_item_names = terminal.select_multiple(
                    format!(
                        "Select one or more {} that you want to delete",
                        Self::ITEM_NAME
                    ),
                    items_names,
                );
                match selected_item_names.len() {
                    0 => {
                        terminal
                            .stdout()
                            .plain(format!("No {} selected to delete", Self::ITEM_NAME))
                            .write_line()?;
                    }
                    1 => {
                        if terminal.confirmed_with_flag_or_prompt(
                            self.cmd_arg_confirm_deletion(),
                            "Are you sure you want to proceed?",
                        )? {
                            self.delete_single().await?;
                        }
                    }
                    _ => {
                        if terminal.confirmed_with_flag_or_prompt(
                            self.cmd_arg_confirm_deletion(),
                            "Are you sure you want to proceed?",
                        )? {
                            self.delete_multiple(selected_item_names).await?;
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
