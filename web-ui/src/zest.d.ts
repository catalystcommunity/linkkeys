// Short global names for the Zest control types. Zest publishes the
// declarations; this file only gives the names that the pages use.
import type { CheckBox, ComboBox, ControlOptionInput, FormControl, PushButton, TextArea, TextField } from "@catalystcommunity/controls";
import type { DateTimePicker } from "@catalystcommunity/date-time-picker";

declare global {
  type ZestControl = FormControl;
  type ZestPushButton = PushButton;
  type ZestTextField = TextField;
  type ZestTextArea = TextArea;
  type ZestCheckBox = CheckBox;
  type ZestComboBox = ComboBox;
  type ZestDateTimePicker = DateTimePicker;
  /** One choice of a combo box. A string is both the value and the label. */
  type ZestOption = ControlOptionInput;
}
