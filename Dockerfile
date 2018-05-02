FROM httpd:alpine AS builder
RUN apk --update add \
  autoconf \
  automake \
  curl-dev \
  g++ \
  glib-dev \
  libtool \
  libxml2-dev \
  make \
  perl-dev \
  py-six \
  python \
  xmlsec-dev \
  zlib-dev

# Install xmlsec
RUN cd /tmp && \
  wget http://www.aleksey.com/xmlsec/download/xmlsec1-1.2.25.tar.gz && \
  tar xzf xmlsec1-1.2.25.tar.gz && \
  cd xmlsec1-1.2.25 && \
  ./configure --enable-soap && \
  make && \
  make install

# Install lasso
RUN cd /tmp && \
  wget https://dev.entrouvert.org/releases/lasso/lasso-2.5.1.tar.gz && \
  tar zxf lasso-2.5.1.tar.gz && \
  cd lasso-2.5.1 && \
  ./configure && \
  make && \
  make install

# Install mod_auth_mellon
COPY . /tmp/mod_auth_mellon
RUN cd /tmp/mod_auth_mellon && \
  aclocal && \
  autoheader && \
  autoconf && \
  ./configure --with-apxs2=/usr/local/apache2/bin/apxs && \
  make && \
  make install

FROM httpd:alpine
RUN apk --update add glib curl libxslt libltdl
COPY --from=builder /usr/local/apache2/modules/mod_auth_mellon.so /usr/local/apache2/modules/mod_auth_mellon.so
COPY --from=builder /usr/local/lib/liblasso* /usr/local/lib/
COPY --from=builder /usr/local/lib/libxmlsec1* /usr/local/lib/
