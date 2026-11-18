# Third-party notices

Code adapted from other projects, with the notices their licences ask to be kept with it. Packages installed through npm, Maven and pip carry their own licences in their packages and are not listed here.

## React Bits

Two dashboard components are adapted from [React Bits](https://reactbits.dev) by David Haz:

| Component here | Adapted from | What was changed |
|---|---|---|
| `dashboard/src/components/BranchedMenu.tsx`, `dashboard/src/styles/branched-menu.css` | Branched Menu | TypeScript; Lucide icons instead of Hugeicons; colours and sizes from the design tokens; the current entry is controlled by the page |
| `dashboard/src/components/LatticeLoader.tsx`, `dashboard/src/styles/lattice-loader.css` | Lattice Loader | TypeScript; one pattern; colours and sizes from the design tokens; the stopwatch counts from a given moment; no live region of its own |

They are used as part of this application, as the licence allows; the components are not sold, sublicensed or redistributed on their own. The licence:

> MIT + Commons Clause License Condition v1.0
>
> Copyright (c) 2026 David Haz
>
> Permission is hereby granted, free of charge, to any person obtaining a copy
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, and distribute the Software **as part of an application, website, or product**, subject to the following conditions:
>
> The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software.
>
> ## Commons Clause Restriction
>
> You may use this Software, including for any commercial purpose, **so long as you do not sell, sublicense, or redistribute the components themselves-whether alone, in a bundle, or as a ported version.**
>
> The same restriction covers the React Bits tools (Background Studio, Texture Lab, Shape Magic, Center Stage, Sound Lab and any tools added later) and the sounds in the sound library. **You may not sell, sublicense, or redistribute the tools or the sounds themselves, or offer the tools or a substantially similar copy of them as a hosted service-whether alone, in a bundle, or as a ported version.**
>
> What you make with the tools is yours to use. You can use exported code, images, videos, and audio files in any personal or commercial application, website, or product, including paid ones. **You may not sell or redistribute the exports on their own, either individually or as the product itself, such as a sound, texture, background, or template pack.**
>
> ## No Warranty
>
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
