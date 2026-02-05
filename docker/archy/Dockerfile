# Base Debian (glibc) — melhor compatibilidade com o binário do Archy
FROM public.ecr.aws/docker/library/node:20-bookworm-slim

# Você pode pin-ar a versão (ex.: 2.36.0) ou usar "latest"
ARG ARCHY_VERSION=2.36.0

# Dependências básicas p/ baixar e descompactar
RUN apt-get update \
  && apt-get install -y --no-install-recommends curl ca-certificates unzip \
  && rm -rf /var/lib/apt/lists/*

# Instala Archy (binário zip oficial)
RUN mkdir -p /opt/archy \
  && curl -fsSL "https://sdk-cdn.mypurecloud.com/archy/2.36.0/archy-linux.zip" -o /tmp/archy.zip \
  && unzip /tmp/archy.zip -d /opt/archy \
  && chmod +x /opt/archy/archy \
  && ln -s /opt/archy/archy /usr/local/bin/archy \
  && rm -f /tmp/archy.zip \
  && mkdir -p /work \
  && ln -s /opt/archy/archyBin /work/archyBin

# (Opcional) usuário não-root
RUN useradd -m -u 10001 archy \
 && mkdir -p /work \
 && chown -R archy:archy /work /opt/archy

USER archy
WORKDIR /work
ENTRYPOINT ["archy"]
