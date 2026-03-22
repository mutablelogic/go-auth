// Carbon Web Components — add or remove component imports here.
// After editing, run `make npm/carbon` from the repo root to rebuild bundle.js.

// Components
import '@carbon/web-components/es/components/ui-shell/index.js';
import '@carbon/web-components/es/components/icon/index.js';
import '@carbon/web-components/es/components/overflow-menu/index.js';
import '@carbon/web-components/es/components/button/index.js';
import '@carbon/web-components/es/components/text-input/index.js';

// Icons
import { geticon, icons } from './icons.js';

globalThis.goWasmBuildCarbonIcons = icons;
globalThis.goWasmBuildCarbonIcon = geticon;
