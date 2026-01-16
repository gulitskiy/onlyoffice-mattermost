// Copyright (c) 2015-present Mattermost, Inc. All Rights Reserved.
// See LICENSE.txt for license information.

/**
 *
 * (c) Copyright Ascensio System SIA 2025
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

import {ONLYOFFICE_PLUGIN_API} from './const';

import type {FileInfo} from 'mattermost-redux/types/files';

/**
 * Generates the editor URL for a given file
 * @param fileInfo - The file information
 * @param lang - Optional language code (defaults to 'en')
 * @param dark - Optional dark theme flag (defaults to false)
 * @returns The full URL to open the file in ONLYOFFICE editor
 */
export function generateEditorUrl(fileInfo: FileInfo, lang?: string, dark?: boolean): string {
    const currentLang = lang || localStorage.getItem('onlyoffice_locale') || 'en';
    // Determine dark theme: use provided value, or check document body class, or default to false
    let isDark = false;
    if (dark !== undefined) {
        isDark = dark;
    } else {
        // Check for dark theme class on body element
        const bodyClasses = document.body.className || '';
        isDark = bodyClasses.includes('theme--dark') || bodyClasses.includes('app__body--dark');
    }
    const baseUrl = window.location.origin;
    const editorPath = `${ONLYOFFICE_PLUGIN_API}/editor?file=${fileInfo.id}&lang=${currentLang}&dark=${isDark}`;
    return `${baseUrl}${editorPath}`;
}

/**
 * Copies the editor URL to the clipboard
 * @param fileInfo - The file information
 * @param lang - Optional language code
 * @param dark - Optional dark theme flag
 * @returns Promise that resolves when the URL is copied, or rejects with an error
 */
export async function copyEditorUrl(fileInfo: FileInfo, lang?: string, dark?: boolean): Promise<void> {
    const url = generateEditorUrl(fileInfo, lang, dark);
    
    try {
        // Try using the modern Clipboard API first
        if (navigator.clipboard && navigator.clipboard.writeText) {
            await navigator.clipboard.writeText(url);
            return;
        }
        
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = url;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            document.body.removeChild(textArea);
        } catch (err) {
            document.body.removeChild(textArea);
            throw err;
        }
    } catch (error) {
        throw new Error('Failed to copy URL to clipboard');
    }
}

