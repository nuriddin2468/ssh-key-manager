/** A small element builder for the popup and the connect page. */
export function h<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { onClick?: () => void; [attribute: string]: string | (() => void) | undefined } = {},
  ...children: (Node | string | null | false)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(props)) {
    if (name === 'onClick') continue;
    if (typeof value === 'string') node.setAttribute(name === 'className' ? 'class' : name, value);
  }
  if (props.onClick) node.addEventListener('click', props.onClick);
  for (const child of children) if (child) node.append(child);
  return node;
}

/** A button; `primary` for the one main action. */
export function button(
  label: string,
  onClick: () => void,
  variant: 'primary' | 'secondary' | 'ghost' | 'danger' = 'secondary',
): HTMLButtonElement {
  const className = variant === 'secondary' ? 'btn' : `btn ${variant}`;
  return h('button', { type: 'button', className, onClick }, label);
}
