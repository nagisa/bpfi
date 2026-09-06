use dynasmrt::{
    DynamicLabel, DynasmApi, DynasmError, DynasmLabelApi, TargetKind,
    components::{LabelRegistry, PatchLoc, RelocRegistry, StaticLabel},
    relocations::Relocation,
};

pub enum Immediate {
    Register(u8),
    Constant(i32),
}

pub enum Offset {
    Register(u8),
    Constant(i16),
}

pub enum Immediate64 {
    Register(u8),
    Constant(u64),
}

/// Trait for assembly generation customization.
///
/// The JIT in this crate primarily implements just the dispatch to this trait and generates the
/// *execution* logic (such as that `add` in BPF is a `addq` in x86.)
///
/// However with the desire that the same code covers generating not just JIT-compiled programs, but
/// also an BPF interpreters, some customization in how code is generated is required.
///
/// For one, for any instructions that operate on the instruction stream data (e.g. an immediate
/// operand) the interpreter usually has to load that value from the instruction stream into a
/// register before it can execute on that value, meanwhile the JIT-compiled program will want to
/// encode the instruction data directly in its generated assembly stream. And so an `add r0, 42`
/// would become a
///
/// ```asm
/// movsx REG_TEMPORARY, [ REG_INSN_STREAM + 4 ]
/// add rsi, REG_TEMPORARY
/// ```
///
/// whereas in JIT compiled version it would be more like
///
/// ```asm
/// add rsi, 42
/// ```
pub trait Assembly {
    type Buffer: dynasmrt::DynasmApi + dynasmrt::DynasmLabelApi;
    fn buffer(&mut self) -> &mut Self::Buffer;

    fn current_imm(&mut self, reg: u8) -> Immediate;
    /// Get the immediate value for a “wide” BPF instruction.
    fn current_imm64(&mut self, reg: u8) -> Immediate64;

    /// Get the dynamic label to the code that the current jump instruction's offset refers to.
    fn current_offset_label(&mut self) -> Option<DynamicLabel>;
    /// Load the offset encoded in the instruction into the provided register.
    fn current_offset_reg(&mut self, reg: u8);
}

#[derive(Debug, thiserror::Error)]
pub enum SliceAssemblerError {
    #[error("write is out of bounds")]
    OutOfBoundWrite,
    #[error("could not resolve a static relocation")]
    ResolveStatic(dynasmrt::DynasmError),
    #[error("could not patch a static relocation")]
    PatchStatic(dynasmrt::DynasmError),
    #[error("could not resolve a dynamic relocation")]
    ResolveDynamic(dynasmrt::DynasmError),
    #[error("could not patch a dynamic relocation")]
    PatchDynamic(dynasmrt::DynasmError),
    #[error("could not define a global label")]
    DefineGlobalLabel(DynasmError),
    #[error("could not define a dynamic label")]
    DefineDynamicLabel(DynasmError),
    #[error("could not patch a value relocation")]
    PatchValueRelocation(DynasmError),
    #[error("could not place a local reference")]
    PlaceLocalReference(DynasmError),
}

/// An assembler that assembles into a provided slice or array.
///
/// If the assembled code does not fit, the assembler will panic. However at the same time the
/// generated dynasm sequences should be for the most part evaluated statically and it should be
/// possible to determine statically if panics are possible or not.
pub struct SliceAssembler<'slice, Reloc: Relocation> {
    base_addr: usize,
    buffer: &'slice mut [u8],
    position: usize,
    labels: LabelRegistry,
    relocs: RelocRegistry<Reloc>,
    error: Option<SliceAssemblerError>,
}

impl<'slice, Reloc: Relocation> SliceAssembler<'slice, Reloc> {
    pub fn new(buffer: &'slice mut [u8], base_addr: usize) -> Self {
        Self {
            buffer,
            base_addr,
            position: 0,
            labels: LabelRegistry::new(),
            relocs: RelocRegistry::new(),
            error: None,
        }
    }

    pub fn commit(&mut self) -> Result<(), SliceAssemblerError> {
        if let Some(e) = self.error.take() {
            return Err(e);
        }
        for (loc, label) in self.relocs.take_statics() {
            let target = self
                .labels
                .resolve_static(&label)
                .map_err(SliceAssemblerError::ResolveStatic)?;
            let buf = &mut self.buffer[loc.range(0)];
            if loc.patch(buf, self.base_addr, target.0).is_err() {
                return Err(SliceAssemblerError::PatchStatic(
                    DynasmError::ImpossibleRelocation(if label.is_global() {
                        TargetKind::Global(label.get_name())
                    } else {
                        TargetKind::Local(label.get_name())
                    }),
                ));
            }
        }
        for (loc, id) in self.relocs.take_dynamics() {
            let target = self
                .labels
                .resolve_dynamic(id)
                .map_err(SliceAssemblerError::ResolveDynamic)?;
            let buf = &mut self.buffer[loc.range(0)];
            if loc.patch(buf, self.base_addr, target.0).is_err() {
                return Err(SliceAssemblerError::PatchDynamic(
                    DynasmError::ImpossibleRelocation(TargetKind::Dynamic(id)),
                ));
            }
        }
        Ok(())
    }
}

impl<'buf, Reloc: Relocation> DynasmApi for SliceAssembler<'buf, Reloc> {
    fn offset(&self) -> dynasmrt::AssemblyOffset {
        dynasmrt::AssemblyOffset(self.position)
    }

    fn push(&mut self, byte: u8) {
        let Some(dest) = self.buffer.get_mut(self.position) else {
            return self.error = Some(SliceAssemblerError::OutOfBoundWrite);
        };
        *dest = byte;
        self.position = self.position.wrapping_add(1);
    }

    fn align(&mut self, alignment: usize, with: u8) {
        let offset = self.offset().0 % alignment;
        if offset != 0 {
            for _ in offset..alignment {
                self.push(with);
            }
        }
    }
}

impl<'buf, Reloc: Relocation> Extend<u8> for SliceAssembler<'buf, Reloc> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        iter.into_iter().for_each(|byte| self.push(byte));
    }
}

impl<'a, 'buf, Reloc: Relocation> Extend<&'a u8> for SliceAssembler<'buf, Reloc> {
    fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
        self.extend(iter.into_iter().copied());
    }
}

impl<'buf, Reloc: Relocation> DynasmLabelApi for SliceAssembler<'buf, Reloc> {
    type Relocation = Reloc;
    fn local_label(&mut self, name: &'static str) {
        self.labels.define_local(name, self.offset());
    }
    fn global_label(&mut self, name: &'static str) {
        if let Err(e) = self.labels.define_global(name, self.offset()) {
            return self.error = Some(SliceAssemblerError::DefineGlobalLabel(e));
        }
    }
    fn dynamic_label(&mut self, id: DynamicLabel) {
        if let Err(e) = self.labels.define_dynamic(id, self.offset()) {
            return self.error = Some(SliceAssemblerError::DefineDynamicLabel(e));
        }
    }
    fn forward_relocation(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: Self::Relocation,
    ) {
        let label = match self.labels.place_local_reference(name) {
            Some(label) => label.next(),
            None => StaticLabel::first(name),
        };
        let patch = PatchLoc::new(self.offset(), target_offset, field_offset, ref_offset, kind);
        self.relocs.add_static(label, patch);
    }
    fn backward_relocation(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: Self::Relocation,
    ) {
        let label = match self.labels.place_local_reference(name) {
            Some(label) => label,
            None => {
                return self.error = Some(SliceAssemblerError::PlaceLocalReference(
                    DynasmError::UnknownLabel(dynasmrt::LabelKind::Local(name)),
                ));
            }
        };
        let patch = PatchLoc::new(self.offset(), target_offset, field_offset, ref_offset, kind);
        self.relocs.add_static(label, patch);
    }
    fn global_relocation(
        &mut self,
        name: &'static str,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: Self::Relocation,
    ) {
        let patch = PatchLoc::new(self.offset(), target_offset, field_offset, ref_offset, kind);
        self.relocs.add_static(StaticLabel::global(name), patch);
    }
    fn dynamic_relocation(
        &mut self,
        id: DynamicLabel,
        target_offset: isize,
        field_offset: u8,
        ref_offset: u8,
        kind: Self::Relocation,
    ) {
        let patch = PatchLoc::new(self.offset(), target_offset, field_offset, ref_offset, kind);
        self.relocs.add_dynamic(id, patch);
    }
    fn value_relocation(
        &mut self,
        value: usize,
        field_offset: u8,
        ref_offset: u8,
        kind: Self::Relocation,
    ) {
        let patch = PatchLoc::new(self.offset(), 0, field_offset, ref_offset, kind);
        let buf = &mut self.buffer[patch.range(0)];
        if patch.patch(buf, self.base_addr, value).is_err() {
            return self.error = Some(SliceAssemblerError::PatchValueRelocation(
                DynasmError::ImpossibleRelocation(TargetKind::Value(value)),
            ));
        }
    }
}
