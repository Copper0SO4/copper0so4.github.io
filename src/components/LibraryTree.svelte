<script lang="ts">
import { onMount } from "svelte";
import type { LibraryNode, LibraryTree } from "../utils/library-utils";

let { tree }: { tree: LibraryTree } = $props();
let expanded = $state<Record<string, boolean>>(
	Object.fromEntries(tree.folderPaths.map((path) => [path, false])),
);
let ready = $state(false);
onMount(() => {
	ready = true;
});

function setAll(open: boolean): void {
	for (const path of tree.folderPaths) expanded[path] = open;
}
</script>

{#snippet icon(kind: "folder" | "article" | "chevron")}
    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="shrink-0">
        {#if kind === "folder"}
            <path d="M3 7V5a2 2 0 0 1 2-2h5l2 3h7a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z" />
            <path d="M3 7h8" />
        {:else if kind === "article"}
            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" />
            <path d="M14 2v6h6M8 13h8M8 17h6" />
        {:else}
            <path d="m9 5 7 7-7 7" />
        {/if}
    </svg>
{/snippet}

{#snippet branches(nodes: LibraryNode[], depth: number)}
    <ul class="min-w-0 space-y-1" class:branch-indent={depth > 0 && depth <= 6}>
        {#each nodes as node (`${node.kind}:${node.path}`)}
            <li class="min-w-0">
                {#if node.kind === "folder"}
                    <details bind:open={expanded[node.path]} data-folder={node.path} class="min-w-0">
                        <summary class="library-row btn-plain !justify-start gap-2 rounded-lg px-3 py-2 font-medium cursor-pointer">
                            <span class="folder-chevron shrink-0 text-50">{@render icon("chevron")}</span>
                            <span class="text-[var(--primary)] shrink-0">{@render icon("folder")}</span>
                            <span class="min-w-0 flex-1 [overflow-wrap:anywhere]">{node.name}</span>
                            <span class="text-50 shrink-0 text-xs font-normal" aria-label={`${node.count} 篇文章`}>{node.count} 篇</span>
                        </summary>
                        {@render branches(node.children, depth + 1)}
                    </details>
                {:else}
                    <a href={node.url} class="library-row btn-plain !justify-start gap-2 rounded-lg py-2 pl-10 pr-3" data-article={node.path}>
                        <span class="text-50 shrink-0">{@render icon("article")}</span>
                        <span class="min-w-0 [overflow-wrap:anywhere]">{node.title}</span>
                    </a>
                {/if}
            </li>
        {/each}
    </ul>
{/snippet}

<div class="library-tree">
    <div class="flex flex-wrap items-center justify-between gap-x-4 gap-y-3 border-b border-[var(--line-divider)] pb-4 mb-4">
        <p class="text-50 text-sm">{tree.articleCount} 篇文章<span class="mx-2 text-30">/</span>{tree.folderPaths.length} 个文件夹</p>
        <div class="flex flex-wrap gap-1" aria-label="目录操作">
            <button type="button" class="btn-plain rounded-lg min-h-11 px-3 text-sm disabled:opacity-40 disabled:cursor-not-allowed" onclick={() => setAll(true)} disabled={!ready || tree.folderPaths.length === 0}>全部展开</button>
            <button type="button" class="btn-plain rounded-lg min-h-11 px-3 text-sm disabled:opacity-40 disabled:cursor-not-allowed" onclick={() => setAll(false)} disabled={!ready || tree.folderPaths.length === 0}>全部折叠</button>
        </div>
    </div>
    {#if tree.articleCount > 0}
        <nav aria-label="知识库文章目录">
            {@render branches(tree.nodes, 0)}
        </nav>
    {:else}
        <p class="text-50 py-10 text-center">知识库暂时还没有文章。</p>
    {/if}
    <noscript><p class="text-50 text-sm mt-4">文件夹可逐个展开；启用 JavaScript 后可使用全部展开和全部折叠。</p></noscript>
</div>

<style>
    .library-row {
        min-height: 2.75rem;
        text-align: start;
    }
    summary {
        list-style: none;
    }
    summary::-webkit-details-marker {
        display: none;
    }
    .folder-chevron {
        transition: transform 150ms ease;
    }
    details[open] > summary .folder-chevron {
        transform: rotate(90deg);
    }
    .branch-indent {
        margin-inline-start: 0.65rem;
        padding-inline-start: clamp(0.5rem, 1.5vw, 1rem);
        border-inline-start: 1px solid var(--line-divider);
    }
    .library-row:focus-visible,
    button:focus-visible {
        outline: 2px solid var(--primary);
        outline-offset: 2px;
    }
    @media (prefers-reduced-motion: reduce) {
        .folder-chevron { transition: none; }
    }
</style>
