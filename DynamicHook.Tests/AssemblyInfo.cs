using Xunit;

// Hook 测试会修改全局 JIT 代码/precode，必须串行执行以避免跨测试干扰。
[assembly: CollectionBehavior(DisableTestParallelization = true)]
