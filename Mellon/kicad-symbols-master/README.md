# LibreSolar schematic symbols library

This library collects symbols used in the different Libre Solar designs. It should be configured as a global library named `LibreSolar`.

## Library design rules

The design rules follow the [KiCad Library Convention](https://kicad-pcb.org/libraries/klc/).

### General rules

- Using a 100mil grid, pin ends and origin must lie on grid nodes.
- Origin is placed in the middle of symbol.
- Field text uses a common size of 50mils.
- The Value field is prefilled with the object name.
- Description and keywords properties contain the relevant information.
- For components with a single default footprint, footprint field is filled with valid entry of the format "Footprint_Library:Footprint_Name" and is set to invisible.

### Basic symbols

- The style of basic shematic symbols (resistor, capacitor, diodes, etc.) should follow the IEC 60617-2 standard.

### Custom ICs (black-box components)

- Pins are grouped logically, not necessarily by pin number.
- Whenever possible, inputs are on the left and outputs are on the right.
- Power supply pins (GND and VCC) are placed left or right. Top and bottom of the symbol are reserved for name and value:
    - Reference designator centered at the top
    - Component value centered at the bottom

## Schematic layout rules

- In order to be compatible with existing libraries, the grid setup should be set to 100 mils.
- The overall schematic should be grouped in hierarchical sub-schematics for easier understanding. The default schematic sheet size should be A4.
- The pins of two devices must always be connected with a wire. It is not allowed to place two devices with their pins together without a wire.
- The text size should be 50mil for standard text and 100mil for headers.
- Each component should have the following component property fields:
    - Reference
    - Value
    - Footprint
    - Datasheet (optional)
    - Manufacturer
    - PartNumber
    - Supplier (optional)
    - OrderNumber (optional)
    - Remarks (optional)
- If the tolerance or voltage of a part is relevant, it should be added in the remarks field and displayed in the schematic.
