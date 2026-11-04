// The part of jsdom's internals that test/user.ts uses.
declare module 'jsdom/lib/generated/idl/utils.js' {
  interface EventTargetImpl {
    _dispatch(event: EventImpl): boolean;
  }
  interface EventImpl {
    isTrusted: boolean;
  }
  export function implForWrapper(wrapper: Event): EventImpl | null;
  export function implForWrapper(wrapper: EventTarget): EventTargetImpl | null;
}
