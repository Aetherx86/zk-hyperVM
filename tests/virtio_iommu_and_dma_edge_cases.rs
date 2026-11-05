use zkhypervm::ept::MemoryOwner;
use zkhypervm::virtio_iommu::{
    PciBdf, SplitVirtqueue, VerifiableIommu, VirtqDesc, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};

#[test]
fn test_virtio_multi_descriptor_chain_minting() {
    let mut vq = SplitVirtqueue::new(1, 0, 128, 0x1000, 0x2000, 0x3000);

    // Chain: Desc 0 -> Desc 1 (read buffer) -> Desc 2 (write buffer)
    let desc0 = VirtqDesc {
        gpa: 0x5000,
        len: 128,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = VirtqDesc {
        gpa: 0x6000,
        len: 256,
        flags: VIRTQ_DESC_F_NEXT,
        next: 2,
    };
    let desc2 = VirtqDesc {
        gpa: 0x7000,
        len: 512,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };

    let descs = [desc0, desc1, desc2];
    let tokens = vq
        .mint_capabilities(
            1, // 1 descriptor chain published
            |_| 0,
            |idx| descs[idx as usize],
            |_| MemoryOwner::VirtioShared(1),
        )
        .unwrap();

    assert_eq!(tokens.len(), 3);
    assert_eq!(vq.active_tokens.get(&0).unwrap().len(), 3);

    // Verify access to each descriptor region
    assert!(vq.verify_access(0x5000, 128, false).is_ok()); // Desc 0 read
    assert!(vq.verify_access(0x6000, 256, false).is_ok()); // Desc 1 read
    assert!(vq.verify_access(0x7000, 512, true).is_ok()); // Desc 2 write

    // Out of bounds check: 0x5000 with len 129 exceeds desc0 capacity
    let oob_res = vq.verify_access(0x5000, 129, false);
    assert!(oob_res.is_err());
    assert_eq!(
        oob_res.err().unwrap(),
        "Host DMA access outside active virtqueue capability interval!"
    );

    // Write violation check: Desc 1 is read-only
    let write_viol = vq.verify_access(0x6000, 64, true);
    assert!(write_viol.is_err());
    assert_eq!(
        write_viol.err().unwrap(),
        "Host write violation on read-only virtqueue buffer!"
    );
}

#[test]
fn test_virtio_capability_revocation_and_overfill_rejection() {
    let mut vq = SplitVirtqueue::new(1, 0, 128, 0x1000, 0x2000, 0x3000);

    let desc = VirtqDesc {
        gpa: 0x8000,
        len: 256,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };

    let _ = vq.mint_capabilities(1, |_| 0, |_| desc, |_| MemoryOwner::VirtioShared(1));

    // Host attempts to report written len > 256 -> rejected
    let overfill_res = vq.complete_descriptor_chain(0, 300);
    assert!(overfill_res.is_err());
    assert_eq!(
        overfill_res.err().unwrap(),
        "Written length exceeds descriptor writable capacity!"
    );

    // Valid completion of 200 bytes
    let completed = vq.complete_descriptor_chain(0, 200);
    assert!(completed.is_ok());
    assert_eq!(vq.last_used_idx, 1);

    // After completion, tokens must be revoked: subsequent access must fail
    let post_revocation = vq.verify_access(0x8000, 64, true);
    assert!(post_revocation.is_err());
    assert_eq!(
        post_revocation.err().unwrap(),
        "Host DMA access outside active virtqueue capability interval!"
    );

    // Second completion of same chain (replay attack) must fail
    let replay_res = vq.complete_descriptor_chain(0, 200);
    assert!(replay_res.is_err());
    assert_eq!(
        replay_res.err().unwrap(),
        "Cannot complete: Descriptor head not active in virtqueue!"
    );
}

#[test]
fn test_iommu_cross_vm_isolation_and_ept_protection() {
    let mut iommu = VerifiableIommu::new(0x10000);

    let bdf_vm1 = PciBdf::new(1, 0, 0); // VM 1 NIC
    let bdf_vm2 = PciBdf::new(2, 0, 0); // VM 2 NVMe

    iommu.assign_device(1, bdf_vm1, 101, 0x20000);
    iommu.assign_device(2, bdf_vm2, 102, 0x30000);

    // 1. VM 1 device accessing VM 1 exclusive memory -> OK
    assert!(iommu
        .verify_dma_access(bdf_vm1, 0x50, MemoryOwner::GuestExclusive(1))
        .is_ok());

    // 2. VM 1 device attempting DMA into VM 2 exclusive memory -> REJECTED
    let cross_res = iommu.verify_dma_access(bdf_vm1, 0x60, MemoryOwner::GuestExclusive(2));
    assert!(cross_res.is_err());
    assert_eq!(
        cross_res.err().unwrap(),
        "IOMMU Violation: Device attempted DMA to unassigned guest exclusive page!"
    );

    // 3. Any device attempting DMA into an EPT tree structure frame -> REJECTED
    let ept_dma_res = iommu.verify_dma_access(bdf_vm1, 0x70, MemoryOwner::EptTree(1));
    assert!(ept_dma_res.is_err());
    assert_eq!(
        ept_dma_res.err().unwrap(),
        "IOMMU Violation: DMA to hypervisor EPT structure forbidden!"
    );

    // 4. Guest device attempting DMA into Host Privileged physical frame -> REJECTED
    let host_dma_res = iommu.verify_dma_access(bdf_vm1, 0x80, MemoryOwner::HostPrivileged);
    assert!(host_dma_res.is_err());
    assert_eq!(
        host_dma_res.err().unwrap(),
        "Guest device attempted DMA to host privileged frame!"
    );

    // 5. Unconfigured BDF -> REJECTED
    let bdf_unknown = PciBdf::new(3, 0, 0);
    let unknown_res = iommu.verify_dma_access(bdf_unknown, 0x90, MemoryOwner::VirtioShared(1));
    assert_eq!(
        unknown_res.err(),
        Some("BDF not configured in IOMMU context table")
    );
}
