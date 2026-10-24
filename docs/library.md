# 知识库维护说明

知识库地址为 `/library/`，桌面导航和移动菜单均提供「知识库」入口。

## 添加文章

照常在 `src/content/posts/` 中添加 Markdown 文章。知识库按文章在此目录内的实际路径分组，显示 frontmatter 的 `title`，链接通过现有 `getPostUrlBySlug` 生成。例如 `Linux/Arch/install.md` 会出现在 `Linux → Arch` 下。根目录文章直接显示在列表中。

新增、删除、移动文件后，下次构建自动更新目录。无需维护另一份文件列表。目录与 `category`、`tags` 完全独立；草稿沿用现有规则：开发环境可见，生产构建隐藏 `draft: true`。

空目录、仅含草稿的目录不会出现在生产知识库中。没有公开文章时显示空状态。目录排序为文件夹优先，再按名称或标题自然排序，支持中文及数字。

## 实现分工

- `src/pages/library.astro`：构建时读取 Astro Content Collections、过滤草稿，并复用 `MainGridLayout`。
- `src/utils/library-utils.ts`：按集合条目的 `id` 构建任意层级目录；使用 `slug` 生成链接，支持自定义 slug。
- `src/components/LibraryTree.svelte`：递归渲染目录，管理全部展开、全部折叠；原生 `details/summary` 支持鼠标、触摸和键盘，未启用 JavaScript 时仍能逐个展开。组件以 `client:load` 挂载，Swup 插入新页面时由 Astro 岛屿机制初始化，无全局监听器。
- `src/config.ts`：统一配置桌面及移动导航入口。
- `src/components/Navbar.astro`：在较窄屏幕使用移动菜单，避免增加入口后平板导航拥挤。

树结构不限深度；视觉缩进最多六层，避免深层目录在手机上不断挤压标题。文章链接与标题仍完整显示，长标题自动换行。配色、卡片、按钮、圆角和主题变量沿用现有 Fuwari。

## 移动文章时注意

移动物理文件可能改变 Astro 默认生成的 slug，进而改变文章 URL。知识库会自动跟随新 URL；已有外部链接和按 pathname 匹配的 Giscus 讨论则仍关联旧 URL。如果需要保留旧链接与评论，请在移动前为文章设置与旧 slug 相同的 frontmatter `slug`（不含 `/posts/` 前缀），再确认构建结果。知识库仍根据新物理目录显示该文章。

## 本地验证

```sh
pnpm check
pnpm build
pnpm exec biome ci ./src --reporter=github
```

开发预览使用 `pnpm dev`；生产预览使用 `pnpm preview`。构建保持完全静态，不需要后端或新增依赖。
