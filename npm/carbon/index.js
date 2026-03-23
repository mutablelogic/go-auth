// Carbon Web Components — add or remove component imports here.
// After editing, run `make npm/carbon` from the repo root to rebuild bundle.js.

// Components
import '@carbon/web-components/es/components/ui-shell/index.js';
import '@carbon/web-components/es/components/ui-shell/header-panel.js';
import '@carbon/web-components/es/components/icon/index.js';
import '@carbon/web-components/es/components/overflow-menu/index.js';
import '@carbon/web-components/es/components/button/index.js';
import '@carbon/web-components/es/components/form/index.js';
import '@carbon/web-components/es/components/dropdown/index.js';
import '@carbon/web-components/es/components/text-input/index.js';
import '@carbon/web-components/es/components/data-table/table.js';
import '@carbon/web-components/es/components/data-table/table-toolbar.js';
import '@carbon/web-components/es/components/data-table/table-toolbar-content.js';
import '@carbon/web-components/es/components/data-table/table-toolbar-search.js';
import '@carbon/web-components/es/components/data-table/table-head.js';
import '@carbon/web-components/es/components/data-table/table-body.js';
import '@carbon/web-components/es/components/data-table/table-header-row.js';
import '@carbon/web-components/es/components/data-table/table-header-cell.js';
import '@carbon/web-components/es/components/data-table/table-row.js';
import '@carbon/web-components/es/components/data-table/table-cell.js';
import '@carbon/web-components/es/components/pagination/index.js';

// Icons
import { geticon, icons } from './icons.js';

globalThis.goWasmBuildCarbonIcons = icons;
globalThis.goWasmBuildCarbonIcon = geticon;
