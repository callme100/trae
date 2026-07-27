新建一个类库项目，默认框架为`.net6`或`.net8`都可以
如果库需要支持多个.net框架，则可以设置其目标框架为多个框架，示例如：`net8.0;net6.0;net40`。
具体可以写哪些框架，可以看这里[支持的目标框架](https://learn.microsoft.com/zh-cn/dotnet/standard/frameworks#how-to-specify-target-frameworks)
编辑项目源文件，加入以下配置（主要最好不要直接编辑项目属性，测试发现其映射支持不太好，特别是`README.MD`文件）：
```
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFrameworks>net8.0;net6.0;net40</TargetFrameworks>
    <PackageId>Crane.MethodHook</PackageId>
	<Title>Crane Method Hook</Title>
    <Version>1.0.2</Version>
    <Authors>Stone.L.Shi</Authors>
    <Company>Chinature</Company>
	<Product>Crane Method Hook</Product>
    <PackageTags>Crane</PackageTags>
    <Description>此库尝试通过汇编JMP指令实现.net中方法钩子。</Description>
    <PackageLicenseExpression>MIT</PackageLicenseExpression>
    <PackageOutputPath>nuget_pack</PackageOutputPath>
    <PackageReleaseNotes>upgrade to support .net 8。</PackageReleaseNotes>
    <PackageReadmeFile>README.md</PackageReadmeFile>
	<GeneratePackageOnBuild>True</GeneratePackageOnBuild>
  </PropertyGroup>

  <ItemGroup>
    <None Include="README.md" Pack="true" PackagePath="\" />
  </ItemGroup>

</Project>
```
然后使用VS开发者控制台命令`dotnet pack`进行打包，
或者直接在项目文件右键点击`重新生成`也会自动打包,
因为项目属性配置了`<GeneratePackageOnBuild>True</GeneratePackageOnBuild>`。

假如需要在生成后对文件进行处理，比如加入混淆，可以在先重新生成一下，保留好Release目录下的文件。
用混淆后的文件替换，然后使用`dotnet pack`命令打包即可。
  
打包后生成的`nupkg`文件其实是标准的zip文件，修改后缀名后解压可以查看包裹内容。  
然后就可以上传到[NuGet官网](https://www.nuget.org/)，上传地址是：[https://www.nuget.org/packages/manage/upload](https://www.nuget.org/packages/manage/upload)。
记住：上传需要有账号（微软账号可以登入），没有就注册一个吧。