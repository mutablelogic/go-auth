// Parts of the certificate and subject pages, which they share

import { html, type TemplateResult } from 'lit';
import { live } from 'lit/directives/live.js';
import { SubjectFields } from './form.ts';
import type { SubjectMeta } from './schema.ts';

import '@carbon/web-components/es/components/text-input/index.js';

// subjectView is a subject's inputs
export function subjectView(subject: SubjectMeta, helper: string): TemplateResult {
    return html`
        <fieldset style="border: 0; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 1rem">
            <legend class="cds--label">Subject</legend>
            <p class="helper">${helper}</p>
            ${SubjectFields.map(({ field, label }) => html`
                <cds-text-input label=${label} .value=${live(subject[field] ?? '')}
                    @input=${(event: Event) => { subject[field] = (event.target as HTMLInputElement).value; }}></cds-text-input>
            `)}
        </fieldset>
    `;
}

// copyText copies the text to the clipboard, which needs a secure page, or
// else selects it in a text area, and copies the selection
export async function copyText(text: string): Promise<void> {
    if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return;
    }
    const area = document.createElement('textarea');
    area.value = text;
    area.setAttribute('readonly', '');
    area.style.position = 'fixed';
    area.style.opacity = '0';
    document.body.append(area);
    area.select();
    document.execCommand('copy');
    area.remove();
}

// formatTime returns a time in the user's locale, or nothing
export function formatTime(value?: string): string {
    if (!value) {
        return '';
    }
    const time = new Date(value);
    return Number.isNaN(time.getTime()) ? value : time.toLocaleString();
}
