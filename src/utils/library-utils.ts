import type { CollectionEntry } from "astro:content";
import { getPostUrlBySlug } from "./url-utils";

export type LibraryArticle = {
	kind: "article";
	path: string;
	title: string;
	url: string;
};

export type LibraryFolder = {
	kind: "folder";
	path: string;
	name: string;
	count: number;
	children: LibraryNode[];
};

export type LibraryNode = LibraryFolder | LibraryArticle;

export type LibraryTree = {
	nodes: LibraryNode[];
	articleCount: number;
	folderPaths: string[];
};

type LibraryPost = Pick<CollectionEntry<"posts">, "id" | "slug" | "data">;

// `id` retains the physical path; `slug` may be overridden in frontmatter.
// Never use category, tags, or slug to decide where a file belongs.
export function buildLibraryTree(posts: LibraryPost[]): LibraryTree {
	const root: LibraryFolder = {
		kind: "folder",
		path: "",
		name: "",
		count: 0,
		children: [],
	};
	const folders = new Map<string, LibraryFolder>([["", root]]);

	for (const post of posts) {
		const segments = post.id.split("/").slice(0, -1);
		let parent = root;
		let path = "";
		parent.count++;
		for (const name of segments) {
			path = path ? `${path}/${name}` : name;
			let folder = folders.get(path);
			if (!folder) {
				folder = { kind: "folder", path, name, count: 0, children: [] };
				folders.set(path, folder);
				parent.children.push(folder);
			}
			folder.count++;
			parent = folder;
		}
		parent.children.push({
			kind: "article",
			path: post.id,
			title: post.data.title,
			url: getPostUrlBySlug(post.slug),
		});
	}

	const collator = new Intl.Collator("zh-CN", {
		numeric: true,
		sensitivity: "base",
	});
	for (const folder of folders.values()) {
		folder.children.sort((a, b) => {
			if (a.kind !== b.kind) return a.kind === "folder" ? -1 : 1;
			const aName = a.kind === "folder" ? a.name : a.title;
			const bName = b.kind === "folder" ? b.name : b.title;
			return collator.compare(aName, bName) || a.path.localeCompare(b.path);
		});
	}

	return {
		nodes: root.children,
		articleCount: root.count,
		folderPaths: [...folders.keys()].filter(Boolean),
	};
}
