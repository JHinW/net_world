---
trigger: always_on
---

## [Critical] What you need to Obey

1. Verify on your own, or ask for help if you come across anything uncertain
  - Always try to validate assumptions and verify results independently first.
  - If you encounter any ambiguities or uncertainties that cannot be resolved on your own, proactively ask the user for clarification or help instead of guessing.

## [Critical] Rules to follow
 
1. Coding is like assigning tasks
  - Before implementing a specific function, it is essential to figure out who bears the primary responsibility.
    - The subject (typically a struct in the coding world) that takes primary responsibility should expose a method and accept the necessary arguments.
    - The owner holding the main responsibility should focus on completing its task and reporting the result.
    - Outside callers do not need to know the internal details used to accomplish the task.

2. Coding is like writing a story: Stories Have Strict Boundaries
  - Once responsibilities per subject are clearly defined, our job is simply to orchestrate the tasks in order.
  - Reading code should feel like reading a story, where actors take action according to their defined roles.
    - As we read or write the code, we naturally and progressively understand what each subject is meant to be.
  - An overarching story is an orchestration of self-contained small stories, where every story has strict boundaries:
    - **Self-contained narratives & clear transitions**: Each small story has its own closed narrative. Entering or exiting a sub-story is typically driven by an actor transitioning to a new scene via a specific event.
    - **A vine, not a mist**: A story is never a diffuse, formless fog; it is an intricate vine with clear beginnings and defined ends.
    - **Skeletal contours & information hiding**: In the broader context, a sub-story only reveals its skeletal outline without exposing internal details. Exposing granular details at the top-level story inevitably leads to narrative breakdown.

3. Creating an Object is Defining an Actor's Boundary of Responsibility and Capability
  - Introducing a `struct`/`class` is fundamentally about establishing a boundary of responsibility and capability for an actor within the narrative.
  - **Bounded capability (Never overstep)**:
    - An actor must strictly operate within its defined identity and competence. It must not know too much or attempt to do everything.
    - Every `struct`/`class` must strictly belong to a well-defined architectural layer (e.g., Domain, Application, Infrastructure), which defines its perspective, lifecycle, and authority.
  - Clear layer and boundary attribution allows any reader to immediately grasp the actor's purpose, scope, and capabilities within the system story.

4. RSI (Similarity & Narrative Alignment): Diagnosing Breakdowns and Managing Similarities Across the Codebase
  - **Narrative perspective on duplication**: Nobody enjoys a story where different characters advance the plot using the exact same actions. When multiple actors perform identical behaviors to push the system forward, it signals narrative redundancy and blurred role identities.
  - **Diagnosing narrative breakdowns**: When code becomes convoluted or the narrative collapses, avoid getting bogged down in low-level implementation details:
    - Never debate granular details in isolation without the overarching skeleton.
    - Never focus solely on execution steps and computed results while ignoring role-responsibility alignment and the caller's perspective.
    - **Role overstepping & behavioral repetition** (actors performing tasks outside their competence, dictating decisions of other domains, or mimicking one another) are the root causes of narrative breakdown.
  - **Uncovering the missing actor**: Duplicated behaviors across distinct subjects typically indicate an unexpressed domain concept or an omitted character. Instead of letting different actors mimic each other or overstep, identify the underlying pattern and introduce a dedicated role (e.g., a domain service, value object, or policy) to own that responsibility.
  - **Realignment and consolidation**: Realignment means verifying whether each actor accomplishes its mission strictly within its bounded responsibility and capability. Actively identify recurring patterns and structural similarities across the codebase, determining whether a unified domain term or concept is needed to abstract and manage them within a cohesive object (Go `struct`, file, or architectural package).

5. Living Business Skeleton (`doc/business_skeleton.md`): Grounding Stories in Real Context
  - **Static code lacks timeline context**: Code only shows the current snapshot, not the cross-team compromises, business design philosophies, or historical revisions that shaped how the inventory story is told.
  - **Read before acting**: Before designing or modifying core business logic, read `doc/business_skeleton.md` to align with the system's context, cross-team contracts, core storylines, and invariants.
  - **Respect deliberate boundaries**: Never "clean up" or bypass a boundary that upholds a documented cross-team contract or historical revision without explicit user confirmation.
  - **Smart Trigger (Human-in-the-Loop)**: When a requirement, design discussion, or code change alters a domain role or cross-team boundary, reshapes a core storyline, touches an invariant, or exposes an undocumented (`[待挖掘]`) area in `doc/business_skeleton.md`, proactively alert the user and suggest invoking the `business-skeleton` skill to mine the underlying context and propose an update. Never silently modify `doc/business_skeleton.md` without user approval.
