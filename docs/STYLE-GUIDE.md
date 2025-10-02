# TRR Repo Style Guide

Below are guidelines for writing TRRs. Some of these may seem random, but we are
adhering to generally-accepted Markdown best practices in an attempt to maximize
compatibility for as many Markdown renderers as possible. Following the
instructions below will stop a lot of common pitfalls.

The repo will automatically lint TRR submissions to help you check for issues. A
compiled release of the linter is also available so you can check before you
submit a pull request. You can find it in the Releases section. Run it from the
root folder in your local directory, and fix any issues that it identifies
before submitting your pull request.

## Markdown syntax

There is a VSCode extension that can identify Markdown syntax problems. It is
highly recommended to use it and address all warnings as they come up.

```text
Name: markdownlint
Id: DavidAnson.vscode-markdownlint
Description: Markdown linting and style checking for Visual Studio Code
Version: 0.58.2
Publisher: David Anson
VS Marketplace Link: https://marketplace.visualstudio.com/items?itemName=DavidAnson.vscode-markdownlint
```

## File and Folder Names

TRRs go in `README.md` files (which will make GitHub render them automatically).
Images and DDMs should be placed in sub-folders called `images` and `ddms`,
respectively. All file and directory names, except `README.md`, should use all
lower case characters and replace spaces with underscores.

**Examples**:

- azure_user_portal.png
- ddm_trr0011_ad_a.json
- usb_topology.gif

## Capitalization

Use the original names of products, tools and binaries, preserving the
capitalization. E.g.:

```markdown
# Markdown style guide

`Markdown` is a dead-simple platform for detection engineering documentation.
```

and not

```markdown
# markdown bad style guide example

`markdown` is a dead-simple platform for detection engineering documentation.
```

## Document layout

We have provided a [template] that defines the higher level layout of a TRR. The
first and second level headings must be in every TRR submission. This helps
ensure consistency across all TRRs. The author has flexibility in how to use
third and lower level headings to organize their work.

## Line Wrapping

Lines should be wrapped at 80 characters. When GitHub creates a diff between
versions, it will include the entire line in the diff, even if just a few
characters where modified. Long sentences result in large diffs and it's
sometimes difficult to determine what has actually changed. An 80 character line
limit means diffs will be more granular and makes it easy to see what actually
changed.

You can use the following VSCode extension to make this easier:

```text
Name: Rewrap
Id: stkb.rewrap
Description: Hard word wrapping for comments and other text at a given column.
Version: 1.16.3
Publisher: stkb
VS Marketplace Link: https://marketplace.visualstudio.com/items?itemName=stkb.rewrap
```

Configure the extension with an 80 character line limit and it will
automatically wrap lines as you type. Additionally, you can press `Alt+q` and
the extension will rewrap the full paragraph for you.

There are a few cases where lines over 80 characters are unavoidable: Markdown
tables, code blocks, and long URLs. In these cases, the 80 char line limit is
not enforced. Our linter automatically excludes these cases, so it's easy to
know if they apply.

## Link Format

Below are three examples of Markdown links:

```markdown
- [url text](https://url.com/path)
- [url]
- [any text here][url]

[url]: https://url.com/path
```

The first is an inline link. The second is using a global link, where the link
target is at the bottom of the file to avoid cluttering up the main content. The
third example is using a global link, but with the link's text being
replaced. This allows you to reuse links, while providing context-specific text.

**For submissions for this repository, please use only global links (the second
and third examples above) in paragraphs.** This makes the markdown easier to
read for reviews. Link style is enforced by the linter, so it will be easy to
identify mistakes.

## Code Blocks and Backticks

Inline code blocks (in Markdown these are created with backticks: \`thing\`)
should be used to differentiate specific instances of things. For example, SSH
is a pronoun for a service, but `ssh` is the specific binary or process. There
may be instances where pronouns vs inline code blocks are confusing. Choose what
you feel works best and be consistent. If others disagree, it will come up in
the pull request.

Fenced code blocks should be used for console logs, json blobs, quotes, or source code:

```text
$ cat main.go
package main

func main() {
    println("hello, world!")
}

$ go run ./main.go
hello, world!
```

## Lists

Lists should use `-` as opposed to `*`. This is because `*` is also used for
italics and emphasis which will confuse the linter tool. Make sure to correctly
use whitespace as well. Examples of good and bad lists are below:

### Good

```text
- Bullet 1
  - Sub-bullet 1
- Bullet 2
- Bullet 3
```

### Bad

```text
*  Bullet 1
  *  Sub-bullet 1
*Bullet 2
*   Bullet 3
```

## Ordered lists

While Markdown will let you created ordered lists using just `1.`, please do not
do that as it's confusing for those reading the raw Markdown files.

### Good

```text
1. Item 1
2. Item 2
3. Item 3
```

### Bad

```text
1.  Item 1
1.Item 2
1.   Item 3
```

[template]: examples/trr0000/win/README.md
