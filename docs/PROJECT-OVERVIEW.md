# Technique Research Reports: Sharing High Quality Threat Research

When creating a detection, a detection engineer (DE) will (hopefully!) follow a
process similar to this:

1. **Research the technique** - some work must be done to understand the attack
   technique that will be detected. Ideally, this is robust and identifies all
   the procedures, but at a minimum there should be some effort to understand
   what the technique looks like.
2. **Identify possible telemetry** - determine what potential telemetry sources
   are available, so the DE knows what options they have to work with.
3. **Select a log source** - a single (or a couple) log sources will be selected
   as the best option for detecting the technique in the target environment.
4. **Build the detection query** - the query logic is actually implemented in a
   specific SIEM. The query also needs to be adapted to the target environment
   to minimize false positives.

Looking at these steps, some of them are universally applicable (those that
involve understanding and identifying the technique) and some are environment
specific (those that involve specific logs sources, SIEMs, and environment noise
and tuning).

![Graphic of universally applicable vs environment specific
tasks](images/project_overview_image1.JPG)

In the InfoSec industry, we share different outputs of all of these steps:
**write-ups** of attack techniques that convey a lot of the research and
**detection queries** that implement a specific detection approach.
Unfortunately, for a detection engineer, both of these vehicles have
shortcomings!

- There are *many* technique write-ups that have been published, but they take
time to sort and digest. Some are excellent: thorough, accurate, and well
presented. Others are boilerplate content on some vendor's blog (and I swear
half of them are AI-generated). And some are downright inaccurate! **What's most
problematic, though, is that the majority of them only cover a single,
well-known procedure.** The end result is that it can take quite a bit of time
to do thorough technique analysis and modeling, even for well-documented
procedures. If you're too hasty about it, you'll have an incomplete
understanding of the technique, resulting in an incomplete detection strategy
and probable gaps in your detection coverage.
- Detection queries are a lossy means of sharing threat information. The act of
creating a detection query involves numerous environment specific decisions:
selecting the best telemetry source available in that environment, determining
which procedures actually apply there (and which are covered by other defensive
layers), what noise to tune out (or not), what query capabilities the SIEM can
support (or the given DE was able to implement), etc. From the point where we
take the universally applicable information and start to make decisions on a
specific detection implementation, we begin losing some information. **The
decisions that are best for one environment may NOT be the best for another, but
the decisions made and details that informed them are not captured in the
detection rule.** This information is lost. This makes detection queries a poor
vehicle to capture and convey information about attack techniques!

## This Repository

Our goal with this project is to offer a single place to share thorough,
accurate, and detailed technique analysis and modeling. TRRs provide the
context, information, and potential telemetry necessary to build a strategy to
detect an attack technique as comprehensively as possible. With this
information, a detection engineer should have no difficulty determining which of
the procedures work in their own environment and what telemetry they have
available. They can save a ton of time yet still deploy a thorough detection
strategy in their environment.

By making the repo open source, we're hoping it can become a force multiplier
for detection engineers throughout the industry: a place to find good technique
analysis and modeling that enables engineers to quickly deploy detections in a
comprehensive detection strategy tailored to their environment. It's also a
great place to showcase your detection engineering skills! Want a future
employer to see what you can really do? Pick an attack technique, do some
mind-blowing analysis and modeling, document it in a TRR, and submit a PR to
have it included in the repo! Cred for you, excellent research for the rest of
us. We all win! :)  

You can get started by reading through the [contribution guide] or [browsing the
repo]. Welcome to the team!

[contribution guide]: CONTRIBUTING.md
[browsing the repo]: https://library.threat-research.org
