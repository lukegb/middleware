# Created by: Cheng-Lung Sung <clsung@FreeBSD.org>
# $FreeBSD$

PORTNAME=	six
PORTVERSION=	1.9.0
CATEGORIES=	devel python
MASTER_SITES=	CHEESESHOP
PKGNAMEPREFIX=	${PYTHON_PKGNAMEPREFIX}

MAINTAINER=	python@FreeBSD.org
COMMENT=	Python 2 and 3 compatibility utilities

LICENSE=	MIT
LICENSE_FILE=	${WRKSRC}/LICENSE

USES=		python:2
USE_PYTHON=	autoplist concurrent distutils

regression-test: build
	@cd ${WRKSRC} && ${PYTHON_CMD} -m pytest -v

.include <bsd.port.mk>
