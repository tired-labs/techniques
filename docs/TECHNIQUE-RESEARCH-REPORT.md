# Technique Research Reports

## Overview

A Technique Research Report (TRR) is a structured document that provides a
detailed, technical understanding of an attack technique. TRRs serve as a
foundational knowledge base for multiple security teams, including detection
engineering, red teaming, incident response, and threat intelligence.

Unlike implementation-specific documentation (e.g., detection queries or
adversary emulation plans), TRRs primarily focus on:

- Understanding the mechanics of a technique
- Modeling the technique
- Defining the distinct procedures that can be used to execute the technique
- Providing a structured resource for various security teams to reference

> [!IMPORTANT]
>
> TRRs do not include implementation details such as detection queries,
> adversary emulation guides, or response playbooks. Instead, they focus on
> breaking down the mechanics of the technique, ensuring that any team can
> derive their own function and environment-specific outputs based on a shared
> technical understanding.

A well-written TRR should be technical enough that any security team can use it
as a reference with minimal additional effort. It should clearly explain how an
attack technique works, identify the distinct procedures, and offer enough
detail that teams can formulate effective strategies for detection engineering,
adversary simulations, or incident response playbooks based on their own needs.

You can browse the repo to see real examples of completed TRRs or view a
light-hearted example with [TRR0001: Smash with a Brick].

### Scope

TRRs are focused on a single, specific attack technique for a specific platform
or set of similar platforms. For example, a single TRR might cover a technique
on the Windows, Linux, and MacOS operating systems, or it might cover only one
of them, depending on how distinct the technique's implementation is for each.

### Existing Frameworks

Unlike traditional frameworks such as MITRE ATT&CK or the Azure Threat Research
Matrix (ATRM), the TRR repository is designed to be independent of any external
classification system. Instead, each documented technique is assigned a unique
TRR ID to ensure that research remains flexible and is not limited by predefined
frameworks. If a technique does map to existing frameworks, those mappings are
included in the metadata for reference but they are not a requirement for a
technique to be documented, nor does a TRR have to adhere to the scope defined
in other frameworks.

## Components of a TRR

Every TRR has a common structure to maintain consistency across reports.
This consistency is critical, ensuring that reports are predictable and
immediately useful to those referencing them. All TRRs are expected to fully
adhere to the established structure, and reports that fail to do so should be
corrected before acceptance into the repository.

### TRR Name

This is the title of the TRR. The name should be specific and depict what is
researched in the report. The wording does not have to mirror existing names
used by other frameworks, but can do so. For example, a TRR could use the
industry's well-known name "DCSync," but a TRR on "Kerberoasting" might be more
accurately named "Roasting Kerberos Service Tickets (Kerberoasting)" to help
distinguish it from "AS-REP Roasting" (a closely related technique that also
roasts Kerberos messages). In these cases, the author is encouraged to use the
most accurate name possible. The well-known name can be included in parenthesis
in the name or in the Technique Overview section (below).

### Metadata

A TRR begins with a section containing metadata which ensures that reports are
categorized properly and easily searchable programmatically and/or through a
separate front-end. This metadata contains fields such as the TRR ID, procedure
IDs, external IDs for mapping to existing frameworks, associated tactics,
relevant platforms, and individual contributors to the content.

A TRR ID follows the format of `TRR####` and is assigned uniquely at the time of
pull request acceptance. This ID will also be used to assign each procedure with
a unique sub-identifier. This ensures that each procedure is independently
trackable and allows more accurate referencing to occur.

While human-readable and detailing valuable information for categorization, this
section is meant to be used primarily for sorting/filtering purposes and should
not contain any supplementary details to help understand the technique
methodology. Those should go in the Technique Overview section.

#### Scope Statement

This optional section can be used to provide details or clarifications about the
scope of the TRR. It shouldn't be necessary for the majority of TRRs.

When this technique is similar, but not identical, to an existing technique
mapped to a preexisting framework, this section can include a summary detailing
how it maps to those related techniques, what platforms it covers, and any
rationale for why and how it deviates from other categorization approaches.

### Technique Overview

Following Metadata, the Technique Overview introduces the attack technique at a
high level. This section is written to be digestible by anyone in cybersecurity,
regardless of technical expertise, and should be clear enough to be copied into
an email or report if leadership requests a summary. Unlike some threat
intelligence reports, a TRR does not track adversary usage or real-world
incidents, as that information is better maintained by Cyber Threat Intelligence
teams.

After reading this section, the reader should understand what the technique is,
how it is generally used, and why adversaries leverage it.

### Technical Background

The Technical Background section provides the foundational technical knowledge
required to understand the technique, explaining key concepts that are common to
all or multiple procedures described in the TRR. It should introduce any
relevant technologies, protocols, or security mechanisms that the technique
interacts with. Additionally, it should describe the security controls that
adversaries exploit, the underlying mechanics of the attack, and why it is
effective. If the technique relies on specific authentication methods, access
controls, or system processes, these details should be outlined. This section
may also touch on common tooling used to execute the technique at a high level.

This section does not contain execution steps, as those are detailed within
individual procedures. Instead, it serves as a prerequisite knowledge base,
making it easier for the reader to understand the mechanics of the technique
without needing to reference external sources.

After reading this section, the reader should understand how the technique
functions and what makes it possible.

### Procedures

The Procedures section is where distinct execution paths for the technique are
documented. A TRR does not treat a technique as a single, monolithic attack
method.  Instead, each distinct execution path is assigned a unique identifier
using the format `TechniqueID.Platform.ProcedureID`. For example, the list of
procedures whose TRR ID is `TRR1000` focusing on a procedure affecting Windows
might have the following procedure IDs:

- `TRR1000.WIN.A` - First execution path
- `TRR1000.WIN.B` - Second execution path
- `TRR1000.WIN.C` - Third execution path
- .... and so on....

> [!IMPORTANT]
>
> We use a different definition of a procedure than some of the common
> frameworks. We define a procedure as a distinct execution path. This means
> that the same set of operations implemented by two different tools or in two
> different programming languages are the same procedure. This allows us to
> focus on unique implementations, which sometimes require different detection
> strategies. For a more in-depth exploration of the topic, see Andrew
> VanVleet's [Improving Threat Identification with Detection Modeling] and Jared
> Atkinsons's [What is a Procedure?].

This section does not go into technical detail, but simply lists a table
similar to the one populated with example data below:

| ID            | Title            | Tactic                      |
|---------------|------------------|-----------------------------|
| TRR1000.WIN.A | Procedure Name 1 | Initial Access              |
| TRR1000.WIN.B | Procedure Name 2 | Execution, Lateral Movement |

After reading this section, the reader should understand how many procedures are
detailed in the TRR, the IDs of these procedures, and the relevant tactics
associated with each.

#### Procedure A: Procedure Name #1

Each procedure is written as a narrative rather than a step-by-step instruction
list. The focus is on explaining the prerequisites, execution mechanics, and
impact of each execution path. If the technique operates differently across
multiple platforms, those variations are documented under separate procedures
or even a separate TRR if no commonalities exist within the same report.

At the end of this section, the reader should have all the information needed to
detail in-depth the specifics of the execution path to accomplish the technique.

##### Detection Data Model (DDM)

This section includes a detection data model (DDM) of the procedure. For
information on how to create a DDM, please see [Improving Threat Identification
with Detection Modeling]. We recommend using the [Arrows app] for the DDM,
because you can save your model as a JSON file for easy sharing and updating.

 Underneath this visualization should be a short summary of what the DDM
represents, calling out any interesting nodes or edges.

#### Procedure B: Procedure Name #2

This section follows the same format as Procedure 1, providing a detailed,
paragraph-style write-up of the execution process.

##### Detection Data Model

This section follows the same format as the DDM in Procedure 1.

## Available Emulation Tests

This section contains a table with links to emulation tests for each procedure
identified, if any are available. It is not necessary to search out emulation
tests, but if the author is aware of any (for example, any Atomic use cases)
they should be included here. This helps detection engineers and red teams
trying to test specific procedures.

| ID            | Link             |
|---------------|------------------|
| TRR0000.WIN.A | [Link1]          |
| TRR0000.WIN.B | [Link2], [Link3] |

### References

Finally, every TRR concludes with a References section with links to external
resources. This section is not meant to duplicate intelligence research but
rather to document the resources used in writing the TRR and provide additional
reading on the topics covered within the report.

[TRR0001: Smash with a Brick]: ../docs/examples/trr0001/README.md
[Improving Threat Identification with Detection Modeling]: https://medium.com/@vanvleet/improving-threat-identification-with-detection-data-models-1cad2f8ce051
[What is a Procedure?]:
    https://posts.specterops.io/on-detection-tactical-to-function-810c14798f63
[Link1]: https://somewhere.on.the.web
[Link2]: https://somewhere.on.the.web
[Link3]: https://somewhere.on.the.web
[Arrows app]: https://arrows.app/
