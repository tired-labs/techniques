# Contribution Guide

Thank you for wanting to contribute to the Technique Research Report (TRR)
Library! The amount of work it takes to research hundreds of attack techniques
across numerous platforms can be overwhelming, but teamwork will accelerate the
pace at which we can chip away at the problem. For more information on this
initiative's goal, please see the [Project Overview] documentation.

Please take a moment to review this document before submitting a pull request.
Following these guidelines helps to communicate that you respect the time of the
repository maintainers. In return, we will reciprocate that respect in assessing
your contribution and helping you finalize your pull requests.

## Getting Started

Contributing to the repository follows the [GitHub Fork Workflow]. To summarize
what this means in practice, a contributor must complete the following steps:

1. TRR scoping
2. Create a fork
3. Write the TRR
4. Create a pull request
5. Address review comments
6. Delete your branch locally

### TRR scoping

The first task is determining the scope of the new TRR. Generally, a TRR should
cover a single attack technique for one platform. It may cover all platforms
where the technique is functionally identical (for example, macOS and Linux
share some identical techniques due to their both being Unix derivatives). Using
a whimsical example, a TRR might cover "X001.001 Eating It" for both the Cakes
and Pies platforms because the steps are very similar for both. But there would
be separate TRRs for Cakes and Pies for "X001.002 Baking It" because the
technique is functionally very different for each.

Unlike traditional frameworks such as MITRE ATT&CK or the Azure Threat Research
Matrix (ATRM), the TRR repository is designed to be independent of any external
classification system. Instead, each documented technique is assigned a unique
TRR ID to ensure that research remains flexible and is not limited by predefined
frameworks. If a technique does map to existing frameworks, those mappings are
included in the metadata for reference but they are not a requirement for a
technique to be documented, nor does a TRR have to adhere to the scope defined
in other frameworks.

> [!TIP]
>
> We are unlikely to accept TRRs for a technique under the "Execution" tactic.
> You can read our reasoning at [Mistaken Identification: When an Attack
> Technique isn't a Technique]. We'll probably ask you to re-scope the TRR to
> whatever technique it's actually addressing.

### Create a fork

Begin by creating a fork of the TRR repository. This will create a local copy of
the repo in your private GitHub account. You can use this personal version to
write your TRR and then submit the changes back to the repository for inclusion.

#### Repo folder structure

The repo uses the following organizational structure:

```text
root
\_reports
  \_trr_id
    \_platform
      |_images
      |_ddms
      |_README.md  (this is the main TRR markdown)
```

Each TRR will be in its own folder under the 'reports' folder, with an `images`
and `ddms` subfolder to hold the images and Detection Data Models (DDMs) used in
the TRR. TRR IDs are assigned incrementally when the TRR is merged into the main
branch, so new TRRs should use "trr0000" as a placeholder. The TRR will be written
in Markdown and will be named "README.md" (this causes GitHub to load it
automatically when displaying the folder).

The name of the platform folder should use the platform name abbreviation
defined in the `platforms.json` file in the root of the repository. This
contains a JSON list of key/value pairs where the key is the platform's full
name and the value is the assigned abbreviation. For example, Azure has been
assigned the abbreviation of `azr`, so a TRR for Azure would be placed in the
folder `/reports/trr0000/azr/`.

There is a [template folder] available that you can use to set up the proper
folder structure and files for a new TRR. Simply copy over the full `trr0000`
folder into the `reports` folder and you start your TRR. You can use the ID "TRR0000"
throughout your new TRR submission, and it will be replaced with an assigned ID when
the TRR is accepted and published.

#### Handling Techniques that Cover Multiple Platforms

If a TRR covers a technique that applies to multiple platforms, list both
platforms in the metadata section and JSON file. Select the platform that seems
the most relevant and place the TRR in a folder with the corresponding
abbreviation. The `platforms` section of the metadata must list this platform
first. This allows readers to find the TRR via the index or the frontend search
using either platform.

For example, a TRR on the technique of stealing credentials from the `NTDS.dit`
file on a Windows domain controller could be stored in a folder named 'win' (for
Windows) or 'ad' (for Active Directory), because the technique applies to both
platforms. The author can select whichever platform seems the best match as the
primary platform. If the author selected "Windows" (because the techniques
addressed were abusing Windows features, for example), they would place the TRR
in the folder `/reports/trr0000/win` and list the platforms as "Windows, Active
Directory."

### Write the TRR

Writing a TRR is not easy and requires a lot of technical expertise. Before you
begin, please read up on the [strategy] that informs this process, [how to do
technique analysis and modeling], and read through a few of the existing TRRs to
get a sense of what we're expecting.

Once you're ready to begin researching and writing, there is a [TRR Guide] with
details on the sections that must be included, a [template], a [style guide], an
[FAQ], and an [example TRR].  

> [!TIP]
>
> If an existing TRR already has a really good explanation of a concept that
> applies to your technique, you should just use it and add to it. There is no
> need to rewrite what has already been written well. Just add whoever wrote it
> as a contributor to the new TRR, to give them credit for their excellent
> explanation.

### Create a pull request

When your TRR is completed, create a new pull request (PR) for your branch. Use
the technique name for the name of your PR. This will trigger the process for
reviewing your TRR for inclusion in the repo.

### Address review comments

Reviewers will leave comments or suggest changes. You should address all
comments and make the requested changes. GitHub provides the platform to have a
conversation between the author and various reviewers, so we can all come to
agreement on how to make the best TRR that we can collectively create. As a best
practice, you should not resolve conversations without the acknowledgement of
the commenter that the issue or recommendation has been addressed. Reviewers
should resolve conversations themselves when they are satisfied with the
conclusion.

Once the required approvals have been obtained, the TRR is ready for inclusion!
The repo maintainers will merge it into the `main` branch, assign it an ID, and
it will be included in the TRR Library. Congratulations and thank you for
contributing!

### Delete your branch locally

The remote branch will be deleted automatically when it is merged, but you might
want to clean up your local repo by deleted merged branches.

[Project Overview]: ./PROJECT-OVERVIEW.md
[GitHub Fork Workflow]: https://gist.github.com/Chaser324/ce0505fbed06b947d962
[TRR Guide]: TECHNIQUE-RESEARCH-REPORT.md
[template]: ./examples/trr0000/win/README.md
[template folder]: ./examples/trr0000/
[style guide]: STYLE-GUIDE.md
[example TRR]: ./examples/trr0001/phy/README.md
[Mistaken Identification: When an Attack Technique isn't a Technique]: https://medium.com/p/8cd9dae6e390
[strategy]: https://medium.com/@vanvleet/threat-detection-strategy-a-visual-model-b8f4fa518441
[how to do technique analysis and modeling]: https://medium.com/@vanvleet/improving-threat-identification-with-detection-data-models-1cad2f8ce051
[FAQ]: FAQ.md
