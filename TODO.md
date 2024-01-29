# To Do List

- [x] Create address groups/network groups/port groups.
- [x] Delete address groups/network groups/port groups.
- [x] Flash messages for actions.
- [x] Update delete rules to list the rules.
- [x] Filter Inbound/Outbound interfaces.
- [x] Live drop-downs for groups/hosts.
- [x] Download configuration commands.
- [x] Upload/download json data.
- [x] User and firewall name to *secure* the configs.
  - [x] Authentication of some form.
- [x] Implement stylesheets.
- [ ] Further implement stylesheets.
- [x] Add delete configuration option.
- [x] Display groups visually.
  - [ ] Make visual display of groups prettier.
- [x] Display chains visually.
- [ ] Display filters visually.

## Design

- [x] Update colors to make more readable
- [ ] Default fields/tabbing order in forms
  - [ ] Short-cuts / tooltips
- [x] & nbsp around bullets and radio buttons
- [ ] Alignment of fields on text forms

      Same with the textfields, I prefer to have a fixed aligned left border. Example at “Add table” and the name and description field who currently just gets “dumped” on the page without alignment. Having it aligned (as in the description text is like in its own column and all the white textfields is in its own column) makes it easier to read and less interrupting the read the whole page.

      Another option if you dont want to have two hidden columns for the description vs textfield is to align it vertically instead as you did over at “Add firewall group” where the field name is in orange (on darkgrey), textfield and then tooltip below it if needed. drawback with vertical alignment is that this is less compact than doing it two-column style.

- [x] Alignment of "choose file"
- [x] Page borders

## Suggested updates/features

- [ ] Email account validation

## Firewall functions

- [ ] Flowtables?
- [x] Firewall group domain-group
- [x] Don't include empty fields like descriptions
- [x] Update all references of tables to chains.
- [ ] Text editor for config

      Another handy thing would be if the generated config would exist in a textarea with a “Update” button at bottom (or top).

      This way one could use the GUI to make a skeleton, click on “Display config” and then copy paste within the textarea (which probably goes way faster) and once done clicking on “Update”. This would be same as if you would first export the generated config, edit the config in notepad/gedit, import it back to the GUI.

- [ ] Look at options for working with official GUI project.

      Other than that this perhaps should/could be merged (or parts of it) with the ongoing VyOS GUI project as described at:
