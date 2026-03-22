import Settings16 from '@carbon/icons/es/settings/16.js';
import Settings20 from '@carbon/icons/es/settings/20.js';
import Checkmark16 from '@carbon/icons/es/checkmark/16.js';
import UserAvatar16 from '@carbon/icons/es/user--avatar/16.js';
import UserAvatar20 from '@carbon/icons/es/user--avatar/20.js';

export const icons = {
    checkmark: {
        16: Checkmark16,
    },
    settings: {
        16: Settings16,
        20: Settings20,
    },
    'user--avatar': {
        16: UserAvatar16,
        20: UserAvatar20,
    },
};

export function geticon(name, size = 16) {
    const entry = icons[name];
    if (!entry) {
        return undefined;
    }
    return entry[size] || entry[16] || entry[20];
}