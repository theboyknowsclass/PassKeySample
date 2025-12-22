FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["PassKeySample.Api/PassKeySample.Api.csproj", "PassKeySample.Api/"]
RUN dotnet restore "PassKeySample.Api/PassKeySample.Api.csproj"
COPY . .
WORKDIR "/src/PassKeySample.Api"
RUN dotnet build "PassKeySample.Api.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "PassKeySample.Api.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app

COPY --from=publish /app/publish .

ENTRYPOINT ["dotnet", "PassKeySample.Api.dll"]

