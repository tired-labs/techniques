# Smash with a Brick

## Metadata

| Key          | Value                                      |
|--------------|-------------------------------------|
| ID           | TRR0001                             |
| External IDs |                                     |
| Tactics      | Initial Access, Impact              |
| Platforms    | Physical                            |
| Contributors | Andrew VanVleet, Adam Przybyszewski |

## Technique Overview

A threat actor could use a brick either as a mechanism to gain physical access
to a machine or as an impact technique to render the machine inoperable.

## Technical Background

Traditionally, the term brick referred to a small unit of building material
consisting primarily of clay. The mineral content of the clay would determine
the brick’s color: clays rich with iron oxide would turn reddish, while clays
containing a lot of lime would have a white or yellow hue.

In current times, the definition of brick has expanded to refer to any small
rectangular building unit that is joined to other units via cementitious mortar
(larger building units are called blocks). Clay is still one of the main brick
materials, but other common materials are sand and lime, concrete, and fly ash.

The materials that a brick is constructed from greatly influence both its
strength and weight. The traditional red clay brick can withstand pressure up to
3000 pounds per square in (PSI) and weighs an average of 5 pounds. Concrete
bricks, on the other hand, are often much larger and denser, usually weighing
aroudn 43 pounds, and can withstand pressure up to 3500 PSI. An attacker's
selection of brick would depend on both the attacker's upper body strength, the
distance from the attacker to the window, and the weight of the brick.

An attacker can determine how much smashing power a given brick might have by
calculating the kinetic energy of the various options. The equation for kinetic
energy is $E_k = \frac{1}{2}mv^2$ where `m` is the mass of the object and `v` is
its velocity.

## Procedures

| ID            | Title           | Tactic         |
|---------------|-----------------|----------------|
| TRR0001.PHY.A | Brick Key       | Initial Access |
| TRR0001.PHY.B | Destructo-brick | Impact         |

### TRR0001.PHY.A: Brick Key

Many sensitive computing systems are secured by physical protections like walls.
Often, those walls will contain doors or windows to allow access or natural
lighting. An attacker can take advantage of this feature by smashing the windows
with a brick, allowing the attacker to bypass normal entry processes and gain
direct access to computer systems.

This attack is most effective in the following circumstances:

- The window is in a door and is wider than the attacker's upper arm, allowing
  him/her to reach through and unlock the door.
- The window is on the first floor and is wider than the attacker's width from
  front to back, measured at the widest point.

#### TRR0001.PHY.A: Detection Data Model (DDM)

![TRR0001.PHY.A DDM](ddms/trr0001.phy.a.png)

### TRR0001.PHY.B: Destructo-brick

An attacker can use the brick to render a system inoperable. This is usually
executed through a series of strong blows with the brick to the casing holding
the system's cricital components like the motherboard and CPU.

An attacker using this technique needs sufficient upper body strength to lift
the brick and bring it back down with sufficient force to crush the housing. For
systems with more durable housing, attackers might try related techniques
referenced in TRR0002 (Spraying with Water) or TRR0003 (Crushing with
Automobile).

#### TRR0001.PHY.B: Detection Data Model (DDM)

![TRR0001.PHY.B DDM](ddms/trr0001.phy.b.png)

Praesent rutrum quis nisi porttitor suscipit. Maecenas sodales velit in mi
vestibulum pellentesque. Etiam consectetur tincidunt diam vitae aliquam. Donec
interdum turpis sed condimentum sodales. Sed eu ultricies justo, sit amet mollis
turpis. Duis bibendum maximus turpis, a volutpat risus condimentum nec. Quisque
in tempor libero. Maecenas hendrerit purus a sapien faucibus accumsan.
Vestibulum fringilla mi urna, ut fringilla nibh commodo a. Pellentesque
scelerisque nulla at bibendum pretium.

## Available Emulation Tests

| ID            | Link             |
|---------------|------------------|
| N/A           | N/A              |

## References

- [How Strong Are Brick Buildings - Modular Clay Products]
- [The Many Types of Bricks - American Ceramic Society]
- [Kinetic Energy - Wikipedia]

[How Strong Are Brick Buildings - Modular Clay Products]: https://www.modularclayproducts.co.uk/news/strength-of-brick-buildings/
[The Many Types of Bricks - American Ceramic Society]: https://ceramics.org/ceramic-tech-today/the-many-types-of-bricks/
[Kinetic Energy - Wikipedia]: https://en.wikipedia.org/wiki/Kinetic_energy
