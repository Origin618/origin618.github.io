/**
 * Based on the discussion at https://github.com/expressive-code/expressive-code/issues/153#issuecomment-2282218684
 */
import { definePlugin } from "@expressive-code/core";

export function pluginLanguageBadge() {
	return definePlugin({
		name: "Language Badge",
		// @ts-ignore
		baseStyles: ({ _cssVar }) => `
      [data-language]::before {
        position: absolute;
        z-index: 2;
        right: 0.5rem;
        top: 0.5rem;
        padding: 0.2rem 0.5rem; 
        content: attr(data-language);
        font-size: 0.75rem;
        font-weight: 600;
        
        /* 🔥 核心修改：删除了 text-transform: uppercase; 🔥 */
        /* 或者你可以写成 text-transform: none; */
        text-transform: none; 
        
        /* 之前的颜色设置保持不变 */
        color: #57606a !important;            
        background: #eaeef2 !important;       
        border: 1px solid #d0d7de !important; 
        
        border-radius: 0.5rem;
        pointer-events: none;
        transition: opacity 0.3s;
        opacity: 0;
      }
      .frame:not(.has-title):not(.is-terminal) {
        @media (hover: none) {
          & [data-language]::before {
            opacity: 1;
            margin-right: 3rem;
          }
          & [data-language]:active::before {
            opacity: 0;
          }
        }
        @media (hover: hover) {
          & [data-language]::before {
            opacity: 1;
          }
          /* 鼠标悬停时隐藏标签 */
          &:hover [data-language]::before {
            opacity: 0;
          }
        }
      }
    `,
	});
}